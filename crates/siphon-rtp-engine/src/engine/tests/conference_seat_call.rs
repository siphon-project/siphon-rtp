//! `conference_seat`: a live call's leg seated in a room where it stands — a subscriber merging two
//! calls into a three-way call, each far party staying on the engine port it already uses.
//!
//! Driven over the control plane with the redirect dispatcher live, on real loopback sockets.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_codec::Decoder as _;
use siphon_rtp_media::rtp::RtpPacket;

/// µ-law full scale and silence.
const LOUD: u8 = 0x00;
const QUIET: u8 = 0xFF;

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

/// A two-party plain G.711 call up through the engine: the subscriber (`near`) and a far party.
struct PlainCall {
    near_phone: UdpSocket,
    far_phone: UdpSocket,
    /// The engine address the subscriber sends to.
    engine_near: SocketAddr,
    /// The engine address the far party sends to, and hears from.
    engine_far: SocketAddr,
}

async fn plain_call(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    far_sdp: impl FnOnce(SocketAddr) -> String,
) -> PlainCall {
    plain_call_with(engine, call_id, |addr| sdp_for(addr, true), far_sdp).await
}

/// [`plain_call`] with the subscriber's offer built by `near_sdp` too.
async fn plain_call_with(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    near_sdp: impl FnOnce(SocketAddr) -> String,
    far_sdp: impl FnOnce(SocketAddr) -> String,
) -> PlainCall {
    let (near_phone, near_addr) = phone().await;
    let (far_phone, far_addr) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: format!("{call_id}-near"),
                sdp: near_sdp(near_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_far = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: format!("{call_id}-near"),
                to_tag: format!("{call_id}-far"),
                sdp: far_sdp(far_addr),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    PlainCall {
        near_phone,
        far_phone,
        engine_near,
        engine_far,
    }
}

async fn seat(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    tag: &str,
    room: &str,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ConferenceSeat {
                call_id: call_id.into(),
                from_tag: tag.into(),
                conference_id: room.into(),
                role: ConferenceRole::Talker,
            },
        )
        .await
}

/// Join a plain third party to `room`, returning its socket and the engine address it talks to.
async fn join_third_party(
    engine: &Engine<UdpLoopbackDatapath>,
    room: &str,
    tag: &str,
) -> (UdpSocket, SocketAddr) {
    let (socket, addr) = phone().await;
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: room.into(),
                from_tag: tag.into(),
                sdp: sdp_for(addr, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_addr = sdp::parse(&ok_sdp_text(&joined))
        .expect("join answer")
        .remote_rtp;
    (socket, engine_addr)
}

/// Drop what reaches `socket` over the next 60 ms (the room keeps sending, so "until empty" would
/// never end).
async fn drain(socket: &UdpSocket) {
    let _ = collect(socket, Duration::from_millis(60)).await;
}

/// Receive datagrams on `socket` for up to `window`, returning each with its source.
async fn collect(socket: &UdpSocket, window: Duration) -> Vec<(Vec<u8>, SocketAddr)> {
    let mut received = Vec::new();
    let mut buffer = [0u8; 2048];
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(Ok((len, from))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        received.push((buffer[..len].to_vec(), from));
    }
    received
}

/// Whether `datagram` is RTCP (RFC 5761 §4: payload-type byte 64..=95 under the marker bit).
fn is_rtcp(datagram: &[u8]) -> bool {
    datagram.len() >= 2 && (64..=95).contains(&(datagram[1] & 0x7f))
}

/// The energy of a G.711 µ-law RTP packet's audio.
fn ulaw_energy(datagram: &[u8]) -> i64 {
    let Ok(packet) = RtpPacket::parse(datagram) else {
        return 0;
    };
    let mut decoder = siphon_rtp_codec::g711::G711::ulaw();
    let mut pcm = vec![0i16; 320];
    let samples = decoder.decode(packet.payload, &mut pcm).unwrap_or(0);
    siphon_rtp_dsp::EnergyVad::energy(&pcm[..samples])
}

/// Keep `speakers` talking (loud) and `quiet` sending silence for `frames` 20 ms frames, then report
/// whether each listener heard loud audio from its engine address.
async fn talk_and_listen(
    speakers: &[(&UdpSocket, SocketAddr, u32)],
    quiet: &[(&UdpSocket, SocketAddr, u32)],
    listeners: &[(&UdpSocket, SocketAddr)],
    start_sequence: u16,
) -> Vec<bool> {
    let mut heard = vec![false; listeners.len()];
    for frame in 0..40u16 {
        let sequence = start_sequence.wrapping_add(frame);
        for (socket, to, ssrc) in speakers {
            socket
                .send_to(&g711_rtp(0, sequence, *ssrc, LOUD), *to)
                .await
                .expect("send");
        }
        for (socket, to, ssrc) in quiet {
            socket
                .send_to(&g711_rtp(0, sequence, *ssrc, QUIET), *to)
                .await
                .expect("send");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        for (index, (socket, from)) in listeners.iter().enumerate() {
            let mut buffer = [0u8; 2048];
            while let Ok(Ok((len, source))) =
                timeout(Duration::from_millis(1), socket.recv_from(&mut buffer)).await
            {
                if source == *from
                    && !is_rtcp(&buffer[..len])
                    && ulaw_energy(&buffer[..len]) > 1_000_000
                {
                    heard[index] = true;
                }
            }
        }
    }
    heard
}

/// The engine endpoint ids of a call's legs, near then far.
fn call_endpoints(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
) -> (EndpointId, Option<EndpointId>) {
    let call = engine.calls.get(call_id).expect("call");
    (call.near.rtp.id, call.far.map(|far| far.rtp.id))
}

/// Two G.711 calls up through the engine on the in-kernel relay; the far leg of each is seated in a
/// room, a third party joins, and all three hear each other mixed-minus-self. Neither seated party
/// was sent any SDP, each keeps hearing the engine from the port it was already using, the room's
/// first packet toward each carries the marker bit, and each first receives an RTCP BYE for the
/// stream the relay had been carrying to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_live_calls_and_a_joiner_hear_each_other_through_seated_legs() {
    let engine = engine_with_dispatcher();
    let x = plain_call(&engine, "call-x", |addr| sdp_for(addr, true)).await;
    let y = plain_call(&engine, "call-y", |addr| sdp_for(addr, true)).await;

    // Both relay in the kernel path before the seat.
    for call_id in ["call-x", "call-y"] {
        let call = engine.calls.get(call_id).expect("call");
        assert_eq!(call.pipeline, PipelineKind::Passthrough);
        assert!(!call.relay_flows.is_empty(), "an in-kernel Forward relay");
    }
    // The subscriber speaks on each call (latching its stream on the relay), and each far party
    // hears it relayed, from the engine port it was given.
    for (call, ssrc) in [(&x, 0x5A5A_0001u32), (&y, 0x5A5A_0002u32)] {
        call.near_phone
            .send_to(&g711_rtp(0, 1, ssrc, LOUD), call.engine_near)
            .await
            .expect("send");
        let (relayed, from) = recv(&call.far_phone).await;
        assert_eq!(from, call.engine_far);
        assert_eq!(&relayed[8..12], &ssrc.to_be_bytes(), "relayed verbatim");
    }
    let (x_near, _) = call_endpoints(&engine, "call-x");
    let (y_near, _) = call_endpoints(&engine, "call-y");

    for (call_id, tag) in [("call-x", "call-x-far"), ("call-y", "call-y-far")] {
        let seated = seat(&engine, call_id, tag, "room-1").await;
        assert!(
            matches!(seated, CmdResult::Ok { sdp: None, .. }),
            "seated, with no SDP for anyone: {seated:?}"
        );
    }
    let (z_phone, engine_z) = join_third_party(&engine, "room-1", "joiner").await;
    assert_eq!(engine.conference().participant_count(), 3);

    // The subscriber's legs were released with the seat: their endpoints are gone.
    assert!(
        engine.datapath().stats(x_near).is_none(),
        "X's peer leg freed"
    );
    assert!(
        engine.datapath().stats(y_near).is_none(),
        "Y's peer leg freed"
    );
    // Each call is still registered, with the seated leg as its one leg.
    for call_id in ["call-x", "call-y"] {
        let call = engine.calls.get(call_id).expect("still registered");
        assert_eq!(call.pipeline, PipelineKind::Seated);
        assert!(call.far.is_none());
        assert_eq!(call.from_tag, format!("{call_id}-far"));
    }

    // The first thing X hears after the move: an RTCP BYE for the subscriber's relayed SSRC, then
    // the room's own stream on a new SSRC whose first packet carries the marker bit.
    x.far_phone
        .send_to(&g711_rtp(0, 2, 0x0A0A_0A0A, QUIET), x.engine_far)
        .await
        .expect("x send");
    let first = collect(&x.far_phone, Duration::from_millis(200)).await;
    assert!(
        first.iter().all(|(_, from)| *from == x.engine_far),
        "everything reaches X from the port it already used"
    );
    let bye_at = first
        .iter()
        .position(|(datagram, _)| {
            is_rtcp(datagram)
                && datagram.len() >= 16
                && datagram[9] == 203
                && datagram[12..16] == 0x5A5A_0001u32.to_be_bytes()
        })
        .expect("an RTCP BYE for the relayed stream");
    let first_mix = first
        .iter()
        .position(|(datagram, _)| !is_rtcp(datagram))
        .expect("the room's stream");
    assert!(bye_at < first_mix, "the BYE precedes the new stream");
    let mix = RtpPacket::parse(&first[first_mix].0).expect("RTP");
    assert!(
        mix.marker,
        "the first packet of the mix carries the marker bit"
    );
    assert_ne!(mix.ssrc, 0x5A5A_0001, "the room originates its own stream");

    // Y talks: X and the joiner hear it, Y does not hear itself.
    drain(&x.far_phone).await;
    drain(&y.far_phone).await;
    let heard = talk_and_listen(
        &[(&y.far_phone, y.engine_far, 0x0B0B_0B0B)],
        &[
            (&x.far_phone, x.engine_far, 0x0A0A_0A0A),
            (&z_phone, engine_z, 0x0C0C_0C0C),
        ],
        &[
            (&x.far_phone, x.engine_far),
            (&z_phone, engine_z),
            (&y.far_phone, y.engine_far),
        ],
        100,
    )
    .await;
    assert_eq!(
        heard,
        vec![true, true, false],
        "X and Z hear Y; Y not itself"
    );

    // The joiner talks: both seated parties hear it on their original ports.
    let heard = talk_and_listen(
        &[(&z_phone, engine_z, 0x0C0C_0C0C)],
        &[
            (&x.far_phone, x.engine_far, 0x0A0A_0A0A),
            (&y.far_phone, y.engine_far, 0x0B0B_0B0B),
        ],
        &[(&x.far_phone, x.engine_far), (&y.far_phone, y.engine_far)],
        200,
    )
    .await;
    assert_eq!(
        heard,
        vec![true, true],
        "both seated parties hear the joiner"
    );
}

/// `delete` on a seated call returns the usual summary, its packet counts spanning before and after
/// the move, and the room's participant count drops by one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_seated_call_reports_counters_from_both_sides_of_the_move() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let x = plain_call(&engine, "call-x", |addr| sdp_for(addr, true)).await;
    let (_z, _) = join_third_party(&engine, "room-1", "joiner").await;

    for sequence in 0..5 {
        x.far_phone
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, QUIET), x.engine_far)
            .await
            .expect("send");
        let _ = recv(&x.near_phone).await;
    }
    assert!(matches!(
        seat(&engine, "call-x", "call-x-far", "room-1").await,
        CmdResult::Ok { .. }
    ));
    for sequence in 5..12 {
        x.far_phone
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, QUIET), x.engine_far)
            .await
            .expect("send");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(engine.conference().participant_count(), 2);

    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "call-x".into(),
                from_tag: "call-x-far".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
    assert_eq!(
        engine.conference().participant_count(),
        1,
        "siphon_rtp_conference_participants drops by one"
    );
    assert!(engine.calls.get("call-x").is_none());
    let summary = std::iter::from_fn(|| events.try_recv().ok())
        .find_map(|event| match event {
            Event::CallSummary { call_id, legs, .. } if call_id == "call-x" => Some(legs),
            _ => None,
        })
        .expect("a call summary");
    assert_eq!(summary.len(), 1, "one leg: the seated one");
    assert_eq!(summary[0].tag, "call-x-far");
    assert!(
        summary[0].packets_in >= 12,
        "five packets before the move and seven after: {}",
        summary[0].packets_in
    );
    assert!(
        summary[0].packets_out > 0,
        "the room's mix counts as the leg's egress"
    );
}

/// A seated leg that stops sending raises `media_timeout` for its call, naming the room, and is
/// still allocated until the controller deletes it. The conference reap does not free it either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_seated_leg_is_reported_against_its_call_and_kept_until_delete() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let x = plain_call(&engine, "call-x", |addr| sdp_for(addr, true)).await;
    assert!(matches!(
        seat(&engine, "call-x", "call-x-far", "room-1").await,
        CmdResult::Ok { .. }
    ));
    let (endpoint, _) = call_endpoints(&engine, "call-x");
    // The seated party talks for a while, then stops.
    for sequence in 0..5 {
        x.far_phone
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, QUIET), x.engine_far)
            .await
            .expect("send");
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    engine.datapath().advance_clock(100);
    assert!(
        engine.reap_idle(30, 0, 30).await.is_empty(),
        "reported, not reaped"
    );
    assert_eq!(
        engine.reap_idle_conferences(30, 0).await,
        0,
        "nor freed by the room"
    );
    let timeouts: Vec<Event> = std::iter::from_fn(|| events.try_recv().ok())
        .filter(|event| matches!(event, Event::MediaTimeout { .. }))
        .collect();
    assert_eq!(
        timeouts,
        vec![Event::MediaTimeout {
            call_id: "call-x".into(),
            from_tag: "call-x-far".into(),
            conference_id: Some("room-1".into()),
            reason: MediaTimeoutReason::NoMedia,
        }]
    );
    assert!(engine.calls.contains_key("call-x"), "still registered");
    assert!(
        engine.datapath().stats(endpoint).is_some(),
        "still allocated"
    );
    assert_eq!(engine.conference().participant_count(), 1, "still seated");

    // Still silent on the next sweep: nothing more is said.
    engine.datapath().advance_clock(10);
    engine.reap_idle(30, 0, 30).await;
    assert!(
        std::iter::from_fn(|| events.try_recv().ok())
            .all(|event| !matches!(event, Event::MediaTimeout { .. })),
        "one report per silence"
    );

    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "call-x".into(),
                from_tag: "call-x-far".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(
        engine.datapath().stats(endpoint).is_none(),
        "delete frees it"
    );
    assert!(!engine.conference().contains("room-1"));
}

/// Every refusal leaves the original two-party call relaying exactly as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_seat_leaves_the_call_relaying() {
    let engine = engine_with_dispatcher();

    // A codec this build decodes but cannot encode (RFC 3389 comfort noise), relayed as is.
    let cn_sdp = |addr: SocketAddr| {
        format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 13\r\na=rtpmap:13 CN/8000\r\na=rtcp-mux\r\n",
            ip = addr.ip(),
            port = addr.port(),
        )
    };
    let cn = plain_call_with(&engine, "call-cn", cn_sdp, cn_sdp).await;
    // A packetization interval past the 120 ms ceiling.
    let long_ptime = plain_call(&engine, "call-ptime", |addr| {
        format!("{}a=ptime:140\r\n", sdp_for(addr, true))
    })
    .await;
    // A tag already seated, and a draining node.
    let taken = plain_call(&engine, "call-taken", |addr| sdp_for(addr, true)).await;
    let (_occupant, _) = join_third_party(&engine, "room-1", "call-taken-far").await;
    let draining = plain_call(&engine, "call-drain", |addr| sdp_for(addr, true)).await;

    let cases: [(&str, &PlainCall, &str); 3] = [
        ("call-cn", &cn, "no encoder"),
        ("call-ptime", &long_ptime, "packetization interval 140"),
        ("call-taken", &taken, "already seated"),
    ];
    for (call_id, call, expected) in cases {
        let refused = seat(&engine, call_id, &format!("{call_id}-far"), "room-1").await;
        assert!(
            matches!(&refused, CmdResult::Error { reason } if reason.contains(expected)),
            "{call_id}: {refused:?}"
        );
        assert_relays(&engine, call_id, call).await;
    }
    engine.handle(CLIENT, Command::Drain).await;
    let refused = seat(&engine, "call-drain", "call-drain-far", "room-2").await;
    assert!(
        matches!(&refused, CmdResult::Error { reason } if reason.contains("draining")),
        "{refused:?}"
    );
    assert_relays(&engine, "call-drain", &draining).await;
    assert!(
        !engine.conference().contains("room-2"),
        "no room left behind"
    );
    assert_eq!(
        engine.conference().participant_count(),
        1,
        "only the occupant is seated"
    );
}

/// The call is the untouched two-party call it was: still both legs, and media still relays both
/// ways between them.
async fn assert_relays(engine: &Engine<UdpLoopbackDatapath>, call_id: &str, call: &PlainCall) {
    {
        let record = engine.calls.get(call_id).expect("still registered");
        assert!(
            record.seat.is_none() && record.far.is_some(),
            "{call_id} untouched"
        );
        assert!(!record.seating, "{call_id} not left locked");
    }
    let to_near = g711_rtp(0, 50, 0x0F0F_0F0F, QUIET);
    call.far_phone
        .send_to(&to_near, call.engine_far)
        .await
        .expect("send");
    let (relayed, _) = recv(&call.near_phone).await;
    assert_eq!(relayed, to_near, "{call_id}: far → near still relays");
    let to_far = g711_rtp(0, 51, 0x0E0E_0E0E, QUIET);
    call.near_phone
        .send_to(&to_far, call.engine_near)
        .await
        .expect("send");
    let (relayed, _) = recv(&call.far_phone).await;
    assert_eq!(relayed, to_far, "{call_id}: near → far still relays");
}

/// `conference_leave` on a seated call's leg returns it to its call as a one-legged call on the same
/// endpoint; it can be seated again, and is freed by `delete`. Verbs that would rebuild its media
/// path are refused naming the room; silence and block gate what the room sends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaving_returns_the_leg_to_its_call_on_the_same_endpoint() {
    let engine = engine_with_dispatcher();
    let x = plain_call(&engine, "call-x", |addr| sdp_for(addr, true)).await;
    let (z_phone, engine_z) = join_third_party(&engine, "room-1", "joiner").await;
    assert!(matches!(
        seat(&engine, "call-x", "call-x-far", "room-1").await,
        CmdResult::Ok { .. }
    ));
    let (endpoint, _) = call_endpoints(&engine, "call-x");

    // A verb that would rebuild the leg's media path is refused, naming the room.
    let refused = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "call-x".into(),
                from_tag: "call-x-far".into(),
                to_tag: None,
                enabled: true,
            },
        )
        .await;
    assert!(
        matches!(&refused, CmdResult::Error { reason } if reason.contains("room-1")),
        "{refused:?}"
    );
    // Silence and block are the room's to apply to the seat.
    for command in [
        Command::SilenceMedia {
            call_id: "call-x".into(),
            from_tag: "call-x-far".into(),
        },
        Command::UnsilenceMedia {
            call_id: "call-x".into(),
            from_tag: "call-x-far".into(),
        },
        Command::BlockMedia {
            call_id: "call-x".into(),
            from_tag: "call-x-far".into(),
        },
    ] {
        let result = engine.handle(CLIENT, command).await;
        assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    }
    let heard = talk_and_listen(
        &[(&z_phone, engine_z, 0x0C0C_0C0C)],
        &[(&x.far_phone, x.engine_far, 0x0A0A_0A0A)],
        &[(&x.far_phone, x.engine_far)],
        10,
    )
    .await;
    assert_eq!(heard, vec![false], "a blocked seat hears nothing");
    let unblocked = engine
        .handle(
            CLIENT,
            Command::UnblockMedia {
                call_id: "call-x".into(),
                from_tag: "call-x-far".into(),
            },
        )
        .await;
    assert!(matches!(unblocked, CmdResult::Ok { .. }));
    let heard = talk_and_listen(
        &[(&z_phone, engine_z, 0x0C0C_0C0C)],
        &[(&x.far_phone, x.engine_far, 0x0A0A_0A0A)],
        &[(&x.far_phone, x.engine_far)],
        60,
    )
    .await;
    assert_eq!(heard, vec![true], "unblocked, it hears the room again");

    let left = engine
        .handle(
            CLIENT,
            Command::ConferenceLeave {
                conference_id: "room-1".into(),
                from_tag: "call-x-far".into(),
            },
        )
        .await;
    assert!(matches!(left, CmdResult::Ok { .. }), "{left:?}");
    assert_eq!(
        engine.conference().participant_count(),
        1,
        "only the joiner"
    );
    {
        let call = engine.calls.get("call-x").expect("back in the registry");
        assert_eq!(call.near.rtp.id, endpoint, "on the same endpoint");
        assert!(call.seat.as_ref().is_some_and(|seat| !seat.seated));
    }
    assert!(engine.datapath().stats(endpoint).is_some(), "not freed");
    let refused = engine
        .handle(
            CLIENT,
            Command::SilenceMedia {
                call_id: "call-x".into(),
                from_tag: "call-x-far".into(),
            },
        )
        .await;
    assert!(
        matches!(&refused, CmdResult::Error { reason } if reason.contains("left conference")),
        "{refused:?}"
    );

    // Seated again — the same leg, the same port — and heard again.
    assert!(matches!(
        seat(&engine, "call-x", "call-x-far", "room-1").await,
        CmdResult::Ok { .. }
    ));
    let heard = talk_and_listen(
        &[(&z_phone, engine_z, 0x0C0C_0C0C)],
        &[(&x.far_phone, x.engine_far, 0x0A0A_0A0A)],
        &[(&x.far_phone, x.engine_far)],
        120,
    )
    .await;
    assert_eq!(heard, vec![true], "re-seated, it hears the room");

    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "call-x".into(),
                from_tag: "call-x-far".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(engine.datapath().stats(endpoint).is_none());
    assert_eq!(engine.conference().participant_count(), 1);
}

/// The seat's events name its call: a digit pressed on the seated leg, and the first packet of a leg
/// seated before it ever sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seated_legs_events_carry_its_call_and_its_room() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let x = plain_call(&engine, "call-x", |addr| {
        format!(
            "{}a=rtpmap:101 telephone-event/8000\r\n",
            sdp_for(addr, true).replace("RTP/AVP 0 8", "RTP/AVP 0 8 101")
        )
    })
    .await;
    assert!(matches!(
        seat(&engine, "call-x", "call-x-far", "room-1").await,
        CmdResult::Ok { .. }
    ));
    // The far party never sent before the seat: its first packet raises `media_started` now.
    let digit = {
        let mut packet = vec![0x80, 101];
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&16_000u32.to_be_bytes());
        packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
        packet.extend_from_slice(&[5, 0x80 | 10, 0x03, 0x20]);
        packet
    };
    x.far_phone
        .send_to(&digit, x.engine_far)
        .await
        .expect("send");
    tokio::time::sleep(Duration::from_millis(100)).await;
    engine.detect_media_started();
    let seen: Vec<Event> = std::iter::from_fn(|| events.try_recv().ok()).collect();
    assert!(
        seen.iter().any(|event| matches!(
            event,
            Event::Dtmf { call_id, from_tag, conference_id: Some(room), digit, .. }
                if call_id == "call-x" && from_tag == "call-x-far" && room == "room-1" && digit == "5"
        )),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|event| matches!(
            event,
            Event::MediaStarted { call_id, from_tag, conference_id: Some(room), .. }
                if call_id == "call-x" && from_tag == "call-x-far" && room == "room-1"
        )),
        "{seen:?}"
    );
}

/// An SDES-SRTP leg is seated with its keys and SRTP contexts intact: the far party keeps
/// encrypting and decrypting under the same keys and the same rollover, with no new negotiation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_srtp_leg_is_seated_with_its_keys_intact() {
    use siphon_rtp_srtp::SrtpContext;

    let engine = engine_with_dispatcher();
    let (near_phone, near_addr) = phone().await;
    let (far_phone, far_addr) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "call-s".into(),
                from_tag: "call-s-near".into(),
                sdp: sdp_for(near_addr, true),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
    let engine_key = *offer_reply.crypto.first().expect("engine a=crypto");
    let engine_far = offer_reply.remote_rtp;
    let far_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "call-s".into(),
                from_tag: "call-s-near".into(),
                to_tag: "call-s-far".into(),
                sdp: savp_answer_sdp(far_addr, &far_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answer, CmdResult::Ok { .. }));
    assert_eq!(
        engine.calls.get("call-s").expect("call").pipeline,
        PipelineKind::Srtp
    );
    // The far party's own contexts, used for the whole call: one per direction.
    let mut far_encrypt = SrtpContext::from_key_material(&far_key.key);
    let mut far_decrypt = SrtpContext::from_key_material(&engine_key.key);
    for sequence in 0..3 {
        let mut sealed = Vec::new();
        far_encrypt
            .protect(&g711_rtp(0, sequence, 0x0A0A_0A0A, QUIET), &mut sealed)
            .expect("protect");
        far_phone.send_to(&sealed, engine_far).await.expect("send");
        let _ = recv(&near_phone).await;
    }

    assert!(matches!(
        seat(&engine, "call-s", "call-s-far", "room-1").await,
        CmdResult::Ok { .. }
    ));
    let (z_phone, engine_z) = join_third_party(&engine, "room-1", "joiner").await;

    // The far party keeps sending under its same context; the joiner hears it.
    let mut heard_far = false;
    let mut heard_joiner = false;
    for sequence in 3..60u16 {
        let mut sealed = Vec::new();
        far_encrypt
            .protect(&g711_rtp(0, sequence, 0x0A0A_0A0A, LOUD), &mut sealed)
            .expect("protect");
        far_phone.send_to(&sealed, engine_far).await.expect("send");
        z_phone
            .send_to(&g711_rtp(0, sequence, 0x0C0C_0C0C, LOUD), engine_z)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut buffer = [0u8; 2048];
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(1), z_phone.recv_from(&mut buffer)).await
        {
            if from == engine_z && ulaw_energy(&buffer[..len]) > 1_000_000 {
                heard_far = true;
            }
        }
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(1), far_phone.recv_from(&mut buffer)).await
        {
            assert_eq!(from, engine_far, "the far party hears its own engine port");
            if is_rtcp(&buffer[..len]) {
                continue;
            }
            let mut clear = Vec::new();
            if far_decrypt.unprotect(&buffer[..len], &mut clear).is_ok()
                && ulaw_energy(&clear) > 1_000_000
            {
                heard_joiner = true;
            }
        }
    }
    assert!(
        heard_far,
        "the room decrypts the far party under its original key"
    );
    assert!(
        heard_joiner,
        "the far party decrypts the mix under the engine's original key"
    );
}

/// A DTLS-SRTP leg is seated with its association intact: no new handshake, and the keys the
/// handshake produced keep working both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_srtp_leg_is_seated_with_its_association_intact() {
    use siphon_rtp_dtls::DtlsCertificate;

    let engine = engine_with_dispatcher();
    let (near_phone, near_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let far_socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind"),
    );
    let far_addr = far_socket.local_addr().expect("addr");
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "call-d".into(),
                from_tag: "call-d-near".into(),
                sdp: sdp_for(near_addr, true),
                profile: ProfileFlags {
                    transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
    let engine_fingerprint = offer_reply.fingerprint.clone().expect("fingerprint");
    let engine_far = offer_reply.remote_rtp;
    let peer_cert = DtlsCertificate::generate().expect("cert");
    let peer_fingerprint = peer_cert.fingerprint();
    let peer_hex = peer_fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "call-d".into(),
                from_tag: "call-d-near".into(),
                to_tag: "call-d-far".into(),
                sdp: format!(
                    "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
                     m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
                     a=setup:active\r\na=fingerprint:{hash} {peer_hex}\r\n",
                    ip = far_addr.ip(),
                    port = far_addr.port(),
                    hash = peer_fingerprint.hash_function,
                ),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answer, CmdResult::Ok { .. }), "{answer:?}");
    let mut far_leg = drive_peer_dtls(
        far_socket.clone(),
        engine_far,
        &peer_cert,
        &engine_fingerprint,
        siphon_rtp_dtls::DtlsRole::Client,
        false,
    )
    .await;
    // Relayed to the plain subscriber before the seat (retrying across the keying window).
    let mut relayed = false;
    for sequence in 0..25 {
        let mut sealed = Vec::new();
        far_leg
            .protect(&g711_rtp(0, sequence, 0x0D0D_0D0D, QUIET), &mut sealed)
            .expect("protect");
        far_socket.send_to(&sealed, engine_far).await.expect("send");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok(_)) = timeout(
            Duration::from_millis(150),
            near_phone.recv_from(&mut buffer),
        )
        .await
        {
            relayed = true;
            break;
        }
    }
    assert!(relayed, "the DTLS call relays before the seat");

    assert!(matches!(
        seat(&engine, "call-d", "call-d-far", "room-1").await,
        CmdResult::Ok { .. }
    ));
    let (z_phone, engine_z) = join_third_party(&engine, "room-1", "joiner").await;

    let mut heard_far = false;
    let mut heard_joiner = false;
    for sequence in 25..90u16 {
        let mut sealed = Vec::new();
        far_leg
            .protect(&g711_rtp(0, sequence, 0x0D0D_0D0D, LOUD), &mut sealed)
            .expect("protect");
        far_socket.send_to(&sealed, engine_far).await.expect("send");
        z_phone
            .send_to(&g711_rtp(0, sequence, 0x0C0C_0C0C, LOUD), engine_z)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut buffer = [0u8; 2048];
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(1), z_phone.recv_from(&mut buffer)).await
        {
            if from == engine_z && ulaw_energy(&buffer[..len]) > 1_000_000 {
                heard_far = true;
            }
        }
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(1), far_socket.recv_from(&mut buffer)).await
        {
            assert_eq!(from, engine_far, "the far party hears its own engine port");
            let mut clear = Vec::new();
            if !is_rtcp(&buffer[..len])
                && far_leg.unprotect(&buffer[..len], &mut clear).is_ok()
                && ulaw_energy(&clear) > 1_000_000
            {
                heard_joiner = true;
            }
        }
    }
    assert!(
        heard_far,
        "the room decrypts the far party with the handshake's key"
    );
    assert!(
        heard_joiner,
        "the far party decrypts the mix with the same association"
    );
}
