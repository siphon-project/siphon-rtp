//! A voice agent driven the way one actually runs: a call that answers, streams its caller to a
//! WebSocket agent server, plays the agent's replies back, and stays up across turns while the
//! agent is silent between them.
//!
//! Nothing in the suite ran that shape. The WebSocket **takeover** bridge was covered by an
//! allocation soak and a re-point leak gate, and both drive *control verbs* rather than a
//! conversation — they attach, detach and re-point, and never push RTP through a call for longer
//! than a churn cycle. Three defects that are only visible in a call carrying real turns therefore
//! shipped, each of them silent in every place an operator would look (the control plane reports
//! the bridge started, the leg counters show healthy `packets_out`, and a capture shows well-formed
//! RTP going to the right address):
//!
//! * a takeover leg stamped media liveness **nowhere**, so the idle sweep reaped it on a fixed
//!   timer however much audio was arriving — a hard cap on call duration at the media timeout,
//!   indistinguishable from the caller hanging up;
//! * the downlink advanced the egress RTP timestamp by one ptime per **WebSocket frame** rather
//!   than by the samples that frame carried, so a server writing 40 ms per turn against a 20 ms
//!   ptime emitted overlapping packets whose timestamps advanced at half the rate of the audio,
//!   and the playout queue drained at half the rate it filled;
//! * a takeover leg emitted nothing at all while the server was quiet, which is most of a
//!   conversation, so the leg read as dead air and its NAT pinhole expired between turns.
//!
//! Each test below is the regression guard for one of those, written against the observable a
//! controller has rather than against the internals: RTP on the wire, and the engine's own
//! reaping decision. Each was checked against the code that carried the defect, not just against
//! the fix: on 0.4.4 all five fail, and on 0.4.5 — which has the liveness fix and not the drain
//! one — the liveness guard passes and the rest still fail.
//!
//! The remaining two tests are the shape itself: one scripted turn end to end, reporting the turn
//! latency the media path contributes, and the leg's bounded playout cap, which is not a defect
//! but is a real constraint on how an agent may write and was not written down anywhere.
//!
//! NIC-free: UDP-loopback datapath, loopback WebSocket server, and the deterministic logical clock
//! the datapath already exposes (`advance_clock`), never `Instant::now()`, so the reaping guard
//! costs milliseconds rather than the 30 s the real timeout would.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use siphon_rtp_codec::g711::G711;
use siphon_rtp_codec::Decoder;
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::Datapath;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher_with_text;
use siphon_rtp_engine::{sdp, ClientId, Engine};
use siphon_rtp_media::bridge::protocol::ControlMessage;
use siphon_rtp_proto::{CmdResult, Command, ProfileFlags};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message;

/// The tests drive the engine as a single control client.
const CLIENT: ClientId = ClientId(1);

/// One 20 ms G.711 frame at 8 kHz.
const SAMPLES_PER_FRAME: usize = 160;

/// The RTP timestamp advance one 20 ms frame is worth at 8 kHz — one tick per sample (RFC 3551 §4.5.14).
const TIMESTAMP_PER_FRAME: u32 = SAMPLES_PER_FRAME as u32;

/// What the agent server is scripted to do once the bridge is up.
enum Agent {
    /// Send nothing at all. The leg is the caller's only far side, so its egress is the engine's
    /// own to render.
    Silent,
    /// Reply once with `frame_ms` of tone per binary frame, `frames` of them, as soon as the first
    /// uplink audio arrives. `frame_ms` deliberately need not equal the leg's ptime — nothing in
    /// the protocol says it must, and a server writing whole turns writes far more than 20 ms.
    ReplyOnFirstUplink { frame_ms: usize, frames: usize },
}

/// A WebSocket agent server on an ephemeral loopback port.
///
/// Returns its URI and a receiver of the uplink audio frames it saw, so a test can order itself
/// against media having actually traversed the bridge rather than against a sleep.
async fn agent_server(script: Agent) -> (String, flume::Receiver<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind agent ws");
    let addr = listener.local_addr().expect("agent ws addr");
    let (uplink_tx, uplink_rx) = flume::unbounded();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept agent ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("agent ws handshake");
        let (mut sink, mut source) = socket.split();

        let mut replied = false;
        while let Some(Ok(message)) = source.next().await {
            match message {
                // The first text frame is `start`, announcing the stream and the negotiated wire
                // format. Everything after it that matters here is binary uplink audio.
                Message::Text(text) => {
                    let _ = ControlMessage::from_json(&text).expect("agent parses control envelope");
                }
                Message::Binary(pcm) => {
                    if uplink_tx.send(pcm.to_vec()).is_err() {
                        break;
                    }
                    if let Agent::ReplyOnFirstUplink { frame_ms, frames } = script {
                        if !replied {
                            replied = true;
                            let samples = 8 * frame_ms;
                            for index in 0..frames {
                                let mut audio = Vec::with_capacity(samples * 2);
                                for sample in 0..samples {
                                    // A square wave whose amplitude *identifies the frame*, so a
                                    // test can say which of the agent's frames reached the caller
                                    // and not merely how many. Square, so the decoded mean square
                                    // is the amplitude squared and the index inverts cleanly.
                                    let magnitude = frame_amplitude(index);
                                    let value = if (sample / 8) % 2 == 0 {
                                        magnitude
                                    } else {
                                        -magnitude
                                    };
                                    audio.extend_from_slice(&value.to_le_bytes());
                                }
                                if sink.send(Message::Binary(audio.into())).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    (format!("ws://{addr}/agent"), uplink_rx)
}

/// A caller: a UDP socket standing in for the handset's media port.
async fn phone() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind phone");
    let addr = socket.local_addr().expect("phone addr");
    (socket, addr)
}

/// A PCMU-only offer from `addr` (RFC 3264). The agent answers it, so the engine is the far side.
fn pcmu_offer(addr: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

fn engine_addr(result: &CmdResult) -> SocketAddr {
    match result {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => sdp::parse(text).expect("parse engine addr").remote_rtp,
        other => panic!("expected Ok with sdp, got {other:?}"),
    }
}

/// One 20 ms PCMU packet: a 12-byte RFC 3550 header plus 160 bytes of µ-law.
///
/// The payload is real µ-law rather than filler because the takeover leg *decodes* it — a bridge
/// that never decoded would pass a fixture of any shape, which is exactly the coverage this file
/// exists to stop relying on.
fn pcmu_packet(ssrc: u32, sequence: u16, timestamp: u32) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12 + SAMPLES_PER_FRAME);
    packet.push(0x80); // V=2, no padding/extension/CSRC
    packet.push(0x00); // M=0, PT=0 (PCMU)
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    for index in 0..SAMPLES_PER_FRAME {
        // A varying, in-band µ-law pattern; 0xFF is µ-law silence, so this is deliberately not that.
        packet.push(0x80u8.wrapping_add((index % 61) as u8));
    }
    packet
}

/// The fields of an egress RTP packet this file asserts on.
///
/// `level` is the decoded mean square of the payload, which is what separates the agent's own
/// audio from the comfort floor the leg renders when the agent is quiet. Without it every
/// assertion here about "the reply" would be satisfied by the floor, and a bridge that dropped the
/// reply entirely would still pass.
#[derive(Debug, Clone, Copy)]
struct Egress {
    sequence: u16,
    timestamp: u32,
    payload_len: usize,
    level: i64,
}

/// Anything above this decoded mean square is the agent speaking rather than the idle floor. The
/// floor is rendered 75 dBov down (`COMFORT_NOISE_LEVEL_DBOV`) and the scripted tone starts at
/// 2000, so the two are orders of magnitude apart and the threshold is not delicate.
const SPEECH_LEVEL: i64 = 100_000;

/// The amplitude that labels the agent's `index`-th reply frame.
///
/// Spread far enough apart that µ-law's log companding — coarse up here, roughly 1 part in 30 at
/// these levels — cannot make two neighbours ambiguous after the round trip.
fn frame_amplitude(index: usize) -> i16 {
    2000 + (index as i16) * 600
}

/// Recover which reply frame a packet carries from its decoded level, inverting
/// [`frame_amplitude`]. `None` for the idle floor.
fn frame_index_of(level: i64) -> Option<usize> {
    if level <= SPEECH_LEVEL {
        return None;
    }
    let amplitude = (level as f64).sqrt();
    let index = ((amplitude - 2000.0) / 600.0).round();
    (index >= 0.0).then_some(index as usize)
}

fn parse_egress(packet: &[u8]) -> Egress {
    assert!(
        packet.len() >= 12,
        "an egress packet is at least an RTP header, got {} bytes",
        packet.len()
    );
    assert_eq!(packet[0] >> 6, 2, "RTP version 2 (RFC 3550 §5.1)");
    let payload = &packet[12..];

    // Decode with the engine's own µ-law decoder rather than a second implementation of it.
    let mut pcm = vec![0i16; SAMPLES_PER_FRAME.max(payload.len())];
    let mut decoder = G711::ulaw();
    let decoded = decoder.decode(payload, &mut pcm).expect("decode µ-law egress");
    let level = if decoded == 0 {
        0
    } else {
        pcm[..decoded]
            .iter()
            .map(|sample| i64::from(*sample) * i64::from(*sample))
            .sum::<i64>()
            / decoded as i64
    };

    Egress {
        sequence: u16::from_be_bytes([packet[2], packet[3]]),
        timestamp: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        payload_len: payload.len(),
        level,
    }
}

/// Collect `count` egress packets from the phone, failing rather than hanging if the leg goes quiet.
async fn collect_egress(socket: &UdpSocket, count: usize) -> Vec<Egress> {
    let mut packets = Vec::with_capacity(count);
    let mut buffer = [0u8; 2048];
    for index in 0..count {
        let (len, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| {
                panic!("egress packet {index} of {count} did not arrive within 2 s — the leg went silent")
            })
            .expect("recv egress");
        packets.push(parse_egress(&buffer[..len]));
    }
    packets
}

/// Stand up an engine with the redirect dispatcher running (a takeover leg's ingress arrives as a
/// `Redirect` datagram, so without the dispatcher nothing reaches the bridge at all), answer a
/// caller with `answer_local` + `ws_uri`, and return the engine and the engine-side media address.
async fn answer_into_agent(
    call_id: &str,
    ws_uri: &str,
    phone_addr: SocketAddr,
    profile: ProfileFlags,
) -> (Arc<Engine<UdpLoopbackDatapath>>, SocketAddr) {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    tokio::spawn(run_redirect_dispatcher_with_text(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.text(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    engine.register_client(CLIENT);

    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: call_id.to_string(),
                from_tag: "caller".into(),
                sdp: pcmu_offer(phone_addr),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri.to_string()),
                    ..profile
                },
            },
        )
        .await;
    let media_addr = engine_addr(&result);
    (engine, media_addr)
}

/// A live takeover leg must not be reaped, however long the call has been up.
///
/// The idle sweep reads the datapath's `last_activity`, which the `Redirect` arm deliberately never
/// writes — each consumer stamps after its own source gate, so a spoofed spray cannot hold a dead
/// path open. The takeover bridge stamped nowhere, so its endpoints sat at the call's `created_tick`
/// for the call's whole life and the sweep tore the call down at the media timeout whatever was
/// arriving. Driven on the logical clock: advance it well past the threshold *first*, then push real
/// media, and the sweep must spare the call on the strength of that media alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_leg_stamps_liveness_so_the_sweep_spares_a_live_call() {
    let (ws_uri, uplink) = agent_server(Agent::Silent).await;
    let (phone_socket, phone_addr) = phone().await;
    let (engine, media_addr) =
        answer_into_agent("live", &ws_uri, phone_addr, ProfileFlags::default()).await;

    // Age the call far past any threshold the sweep could be run with, with no media at all.
    engine.datapath().advance_clock(50);

    // Now the caller speaks. This is the only thing that may keep the call alive.
    for frame in 0..5u32 {
        phone_socket
            .send_to(
                &pcmu_packet(0x0BADC0DE, frame as u16, frame * TIMESTAMP_PER_FRAME),
                media_addr,
            )
            .await
            .expect("send caller media");
    }

    // Order against the media having actually traversed the bridge, rather than against a sleep:
    // the agent server received uplink audio, so ingress was accepted and stamped.
    timeout(Duration::from_secs(2), uplink.recv_async())
        .await
        .expect("uplink audio reached the agent within 2 s")
        .expect("agent uplink channel open");

    assert!(
        engine.reap_idle(5).await.is_empty(),
        "a takeover leg carrying media must not be reaped: the caller's audio arrived after the \
         clock advanced, so the sweep has fresh liveness to read and the call is plainly alive"
    );
    assert_eq!(engine.session_count(), 1, "the call is still up");

    // The converse, so the guard cannot pass by the sweep simply never reaping anything: with the
    // media stopped and the clock advanced again, the same call is reaped.
    engine.datapath().advance_clock(50);
    assert_eq!(
        engine.reap_idle(5).await,
        vec!["live".to_string()],
        "a takeover leg that genuinely went quiet is still reaped"
    );
}

/// A server frame longer than the leg's ptime must be repacketized onto the leg's own clock.
///
/// Nothing in the protocol says a server writes one frame per ptime, and a server writing whole
/// turns writes far more. The bridge advanced the egress timestamp by one ptime per frame received
/// rather than by the samples it carried, so 40 ms frames against a 20 ms ptime went out as
/// oversized packets whose timestamps advanced at half the rate of the audio — every packet
/// overlapping its predecessor, and the handset playing nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_server_frame_longer_than_the_ptime_drains_one_ptime_per_tick() {
    // Four 40 ms frames: eight 20 ms packets' worth of audio, written in half as many frames.
    let (ws_uri, _uplink) = agent_server(Agent::ReplyOnFirstUplink {
        frame_ms: 40,
        frames: 4,
    })
    .await;
    let (phone_socket, phone_addr) = phone().await;
    let (_engine, media_addr) =
        answer_into_agent("longframe", &ws_uri, phone_addr, ProfileFlags::default()).await;

    // One caller frame triggers the scripted reply.
    phone_socket
        .send_to(&pcmu_packet(0x0BADC0DE, 0, 0), media_addr)
        .await
        .expect("send caller media");

    // Enough egress to contain the whole reply plus idle floor either side of it.
    let packets = collect_egress(&phone_socket, 30).await;

    // Every packet, reply or floor, is one ptime. An oversized packet is the defect's signature:
    // the bridge emitting the server's 40 ms frame verbatim.
    for (index, packet) in packets.iter().enumerate() {
        assert_eq!(
            packet.payload_len, SAMPLES_PER_FRAME,
            "packet {index} carries exactly one ptime of µ-law ({SAMPLES_PER_FRAME} bytes), not \
             whatever the server happened to frame — got {}",
            packet.payload_len
        );
    }

    // The reply is the contiguous run of packets carrying real audio rather than the idle floor.
    let speech: Vec<usize> = packets
        .iter()
        .enumerate()
        .filter(|(_, packet)| packet.level > SPEECH_LEVEL)
        .map(|(index, _)| index)
        .collect();
    assert!(
        !speech.is_empty(),
        "the agent's reply never reached the caller: every egress packet was at the idle floor"
    );
    assert_eq!(
        speech.len(),
        8,
        "four 40 ms server frames are 160 ms of audio, which is eight 20 ms packets on the leg's \
         own clock — got {}, so the bridge is repacketizing on the server's framing rather than \
         the leg's",
        speech.len()
    );

    // Each 40 ms server frame carries its own amplitude, so it should appear as exactly two
    // consecutive 20 ms packets, in the order the server wrote them. That is the property the
    // defect broke: it emitted one packet per server frame and stamped it as a single ptime.
    //
    // Contiguity of the whole run is deliberately *not* asserted. The agent writes its four frames
    // back to back, so whether a tick ever finds the ring momentarily empty between them depends
    // on scheduling, and an idle-floor packet slipping into the middle is not this defect.
    let carried: Vec<usize> = packets
        .iter()
        .filter_map(|packet| frame_index_of(packet.level))
        .collect();
    assert_eq!(
        carried,
        vec![0, 0, 1, 1, 2, 2, 3, 3],
        "each 40 ms server frame becomes two 20 ms packets, in order"
    );

    for pair in packets.windows(2) {
        let (previous, next) = (pair[0], pair[1]);
        assert_eq!(
            next.sequence,
            previous.sequence.wrapping_add(1),
            "egress sequence numbers are consecutive (RFC 3550 §5.1)"
        );
        assert_eq!(
            next.timestamp.wrapping_sub(previous.timestamp),
            TIMESTAMP_PER_FRAME,
            "the egress timestamp advances by the samples the packet carries, so audio plays at \
             its own rate: {} to {} is not one 20 ms frame",
            previous.timestamp,
            next.timestamp
        );
    }
}

/// A takeover leg is the caller's only far side, so it must keep emitting while the agent is quiet.
///
/// There is no second party whose media holds the return path open. A leg that emits nothing
/// between turns reads as dead air to the caller and lets its NAT pinhole expire, and "between
/// turns" is most of a conversation. An underrun renders a comfort floor on the leg's own codec
/// rather than stopping the clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_quiet_agent_still_holds_the_return_path_open() {
    let (ws_uri, uplink) = agent_server(Agent::Silent).await;
    let (phone_socket, phone_addr) = phone().await;
    let (_engine, media_addr) =
        answer_into_agent("quiet", &ws_uri, phone_addr, ProfileFlags::default()).await;

    phone_socket
        .send_to(&pcmu_packet(0x0BADC0DE, 0, 0), media_addr)
        .await
        .expect("send caller media");
    timeout(Duration::from_secs(2), uplink.recv_async())
        .await
        .expect("uplink audio reached the agent within 2 s")
        .expect("agent uplink channel open");

    // The agent has said nothing and will say nothing. The leg must still be running its clock.
    let packets = collect_egress(&phone_socket, 10).await;
    for (index, packet) in packets.iter().enumerate() {
        assert_eq!(
            packet.payload_len, SAMPLES_PER_FRAME,
            "comfort-floor packet {index} is a full ptime"
        );
    }
    for pair in packets.windows(2) {
        assert_eq!(
            pair[1].timestamp.wrapping_sub(pair[0].timestamp),
            TIMESTAMP_PER_FRAME,
            "the egress clock keeps running while the agent is silent"
        );
        assert_eq!(
            pair[1].sequence,
            pair[0].sequence.wrapping_add(1),
            "and its sequence stays consecutive, so the caller hears a continuous stream"
        );
    }
}

/// The shape itself: a caller speaks, the agent replies, and the media path's contribution to the
/// turn is measured.
///
/// This is the seed of the concurrency harness — one session, scripted, with the turn boundary
/// timed on the wire. It asserts the conversation completes and reports the latency rather than
/// gating on an absolute figure, because the number is hardware- and scheduler-dependent and a
/// threshold here would be a flake. What it does gate on is that the reply is audible: the egress
/// carries the agent's audio, coherently, on the leg's clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_scripted_turn_completes_and_reports_its_media_path_latency() {
    // Eight frames: a reply that fits the leg's playout cap, so nothing is dropped and the whole
    // turn is expected on the wire. A bigger burst is its own test below.
    let (ws_uri, uplink) = agent_server(Agent::ReplyOnFirstUplink {
        frame_ms: 20,
        frames: 8,
    })
    .await;
    let (phone_socket, phone_addr) = phone().await;
    let (engine, media_addr) =
        answer_into_agent("turn", &ws_uri, phone_addr, ProfileFlags::default()).await;

    // The caller's turn: 200 ms of speech.
    let spoke_at = Instant::now();
    for frame in 0..10u32 {
        phone_socket
            .send_to(
                &pcmu_packet(0x0BADC0DE, frame as u16, frame * TIMESTAMP_PER_FRAME),
                media_addr,
            )
            .await
            .expect("send caller media");
    }
    timeout(Duration::from_secs(2), uplink.recv_async())
        .await
        .expect("the agent heard the caller within 2 s")
        .expect("agent uplink channel open");

    // The agent's turn, back on the wire.
    let packets = collect_egress(&phone_socket, 20).await;
    let turn_latency = spoke_at.elapsed();

    for pair in packets.windows(2) {
        assert_eq!(
            pair[1].timestamp.wrapping_sub(pair[0].timestamp),
            TIMESTAMP_PER_FRAME,
            "the reply plays at its own rate"
        );
    }
    // Every frame the agent spoke reaches the caller, in the order it was spoken. Identity, not
    // just count: a bridge that played the right number of frames in the wrong order, or replayed
    // one, would satisfy a count and still be broken audio.
    let spoken: Vec<usize> = packets
        .iter()
        .filter_map(|packet| frame_index_of(packet.level))
        .collect();
    assert_eq!(
        spoken,
        (0..8).collect::<Vec<_>>(),
        "the caller hears the agent's eight frames, in order"
    );
    assert_eq!(engine.session_count(), 1, "the call survives its first turn");

    // Reported, not asserted: the media path's own contribution to a turn, which is the term a
    // deployment can actually influence (the rest is vendor latency in the agent).
    println!(
        "media-path turn latency: {turn_latency:?} over {} packets",
        packets.len()
    );
}

/// A whole turn written in one burst overruns the leg's playout cap, and the *newest* audio wins.
///
/// The playout ring is bounded and drop-oldest on purpose — late audio is worthless, and an
/// unbounded queue is how a traffic spike becomes an OOM. But the consequence is a real constraint
/// on how an agent may write, and it is not otherwise written down anywhere: a server that dumps
/// 320 ms of reply into a 160 ms ring faster than the leg drains it loses the *front* of its own
/// sentence. An agent must pace its writes to roughly real time, or stage them somewhere that is
/// not this ring.
///
/// Pinned deliberately rather than discovered again later: this is the same ring any future
/// staged-playout ("speak the reply I prepared, now") work has to reckon with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_larger_than_the_playout_cap_keeps_the_newest_audio() {
    // Sixteen 20 ms frames, written as fast as the socket takes them: double the ring.
    let (ws_uri, uplink) = agent_server(Agent::ReplyOnFirstUplink {
        frame_ms: 20,
        frames: 16,
    })
    .await;
    let (phone_socket, phone_addr) = phone().await;
    let (_engine, media_addr) =
        answer_into_agent("burst", &ws_uri, phone_addr, ProfileFlags::default()).await;

    phone_socket
        .send_to(&pcmu_packet(0x0BADC0DE, 0, 0), media_addr)
        .await
        .expect("send caller media");
    timeout(Duration::from_secs(2), uplink.recv_async())
        .await
        .expect("the agent heard the caller within 2 s")
        .expect("agent uplink channel open");

    let packets = collect_egress(&phone_socket, 30).await;
    let spoken: Vec<usize> = packets
        .iter()
        .filter_map(|packet| frame_index_of(packet.level))
        .collect();

    assert!(
        !spoken.is_empty(),
        "some of the burst must reach the caller"
    );
    assert!(
        spoken.len() < 16,
        "a 16-frame burst cannot survive an 8-frame ring intact — if it did, the ring grew, which \
         is the unbounded-queue failure the cap exists to prevent (got {})",
        spoken.len()
    );
    assert!(
        spoken.windows(2).all(|pair| pair[1] > pair[0]),
        "what does survive is still in the order it was spoken, never replayed or reordered: \
         {spoken:?}"
    );

    // The discriminator between drop-oldest and drop-newest. Under drop-newest the caller would
    // hear the *start* of the burst and the sentence would stop early; under drop-oldest the
    // newest audio is what is left, so the run ends on the last frame the agent wrote.
    //
    // Only the suffix is pinned. Whether an early frame also escapes depends on how many ticks the
    // leg happened to drain before the rest of the burst landed, which is scheduler-dependent and
    // is exactly the kind of thing that would flake if asserted (an observed run is `[0, 8..=15]`).
    let tail_start = spoken
        .iter()
        .rposition(|index| *index == 15)
        .map(|position| {
            let mut start = position;
            while start > 0 && spoken[start - 1] + 1 == spoken[start] {
                start -= 1;
            }
            start
        })
        .expect("the newest frame the agent wrote must reach the caller");
    let tail = &spoken[tail_start..];
    assert!(
        tail.len() >= 6,
        "the ring should still be holding most of its capacity in newest audio, got {tail:?}"
    );
    assert_eq!(
        *tail.last().expect("non-empty"),
        15,
        "the run ends on the agent's last frame"
    );
}
