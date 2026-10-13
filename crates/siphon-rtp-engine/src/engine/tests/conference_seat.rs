//! Which codec `conference_join` seats a participant in, and the error a join is answered with when
//! the room cannot hold the seat.
//!
//! The answer SDP is read here line by line, never through `sdp::parse`: the engine's own reader
//! agreeing with its own writer says nothing about either.

use super::*;

/// The audio formats of a terminal's offer, by payload type: `a=rtpmap` encoding and `a=fmtp`
/// parameters. AMR-WB is offered in both RFC 4867 payload formats, bandwidth-efficient first, as
/// 3GPP TS 26.114 Table A.3.1 has a terminal do. EVS is one the engine cannot decode.
const TERMINAL_FORMATS: [(u8, &str, &str); 6] = [
    (110, "EVS/16000", "br=5.9-24.4;bw=nb-swb;max-red=220"),
    (104, "AMR-WB/16000", "mode-change-capability=2;max-red=220"),
    (
        106,
        "AMR-WB/16000",
        "mode-change-capability=2;max-red=220;octet-align=1",
    ),
    (102, "AMR/8000", "mode-change-capability=2;max-red=220"),
    (105, "telephone-event/16000", "0-15"),
    (100, "telephone-event/8000", "0-15"),
];

/// The terminal's full offer: EVS first, AMR-WB in both payload formats, AMR, both events.
const VOLTE: [u8; 6] = [110, 104, 106, 102, 105, 100];

/// A terminal's offer from `rtp`, listing `payload_types` in that order.
fn terminal_offer(rtp: SocketAddr, payload_types: &[u8]) -> String {
    let formats: Vec<String> = payload_types.iter().map(u8::to_string).collect();
    let mut offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {formats}\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
        formats = formats.join(" "),
    );
    for payload_type in payload_types {
        let (_, encoding, parameters) = TERMINAL_FORMATS
            .iter()
            .find(|(number, _, _)| number == payload_type)
            .expect("a format of the terminal");
        offer.push_str(&format!(
            "a=rtpmap:{payload_type} {encoding}\r\na=fmtp:{payload_type} {parameters}\r\n"
        ));
    }
    offer.push_str("a=ptime:20\r\na=maxptime:240\r\na=sendrecv\r\na=rtcp-mux\r\n");
    offer
}

/// An offer from `rtp` of static G.711 payload types `payload_types`, packetized at `ptime_ms`.
fn g711_offer(rtp: SocketAddr, payload_types: &[u8], ptime_ms: u8) -> String {
    let formats: Vec<String> = payload_types.iter().map(u8::to_string).collect();
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {formats} 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:{ptime_ms}\r\n\
         a=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
        formats = formats.join(" "),
    )
}

/// `conference_join` of `from_tag` into `conference_id` with the codec directives `flags`.
async fn join(
    engine: &Engine<UdpLoopbackDatapath>,
    conference_id: &str,
    from_tag: &str,
    sdp: String,
    flags: &[&str],
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: conference_id.into(),
                from_tag: from_tag.into(),
                sdp,
                role: ConferenceRole::Talker,
                profile: ProfileFlags {
                    flags: flags.iter().map(|flag| (*flag).to_string()).collect(),
                    ..Default::default()
                },
            },
        )
        .await
}

/// The reason of a refused command.
fn refusal(result: &CmdResult) -> &str {
    match result {
        CmdResult::Error { reason } => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// The format list of the `m=audio` line (RFC 4566 §5.14), read off the text.
fn audio_formats(sdp: &str) -> String {
    let media = sdp
        .lines()
        .find(|line| line.starts_with("m=audio "))
        .expect("an m=audio line");
    media.splitn(4, ' ').nth(3).unwrap_or_default().to_string()
}

/// The `m=audio` port of an answer, read off the text.
#[cfg(feature = "amr")]
fn audio_port(sdp: &str) -> u16 {
    sdp.lines()
        .find_map(|line| line.strip_prefix("m=audio "))
        .and_then(|rest| rest.split(' ').next())
        .and_then(|port| port.parse().ok())
        .expect("an m=audio port")
}

/// Every `a=rtpmap` and `a=fmtp` value of the body, in the order written.
#[cfg(feature = "amr")]
fn codec_lines(sdp: &str) -> Vec<&str> {
    sdp.lines()
        .filter(|line| line.starts_with("a=rtpmap:") || line.starts_with("a=fmtp:"))
        .collect()
}

/// The known-answer case. A terminal offers EVS first, AMR-WB in both payload formats, AMR, and
/// telephone-event at both clock rates. The room seats it in AMR-WB, the first offered codec it can
/// decode and encode, in the bandwidth-efficient format listed first, and answers that payload type
/// with the parameters it was offered and the 16 kHz event.
#[cfg(feature = "amr")]
#[tokio::test]
async fn a_terminal_offer_led_by_evs_is_seated_in_amr_wb() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal) = phone().await;
    let joined = join(
        &engine,
        "room",
        "terminal",
        terminal_offer(terminal, &VOLTE),
        &[],
    )
    .await;
    let answer = ok_sdp_text(&joined);
    assert_eq!(audio_formats(&answer), "104 105", "{answer}");
    assert_eq!(
        codec_lines(&answer),
        [
            "a=rtpmap:104 AMR-WB/16000",
            "a=fmtp:104 mode-change-capability=2;max-red=220",
            "a=rtpmap:105 telephone-event/16000",
        ],
        "{answer}"
    );
    assert!(answer.contains("a=ptime:20\r\n"), "{answer}");
    assert!(answer.contains("a=sendrecv\r\n"), "{answer}");
}

/// The octet-aligned AMR-WB payload type, offered first, is the one answered, with `octet-align=1`.
#[cfg(feature = "amr")]
#[tokio::test]
async fn an_octet_aligned_amr_wb_offer_is_answered_octet_aligned() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal) = phone().await;
    let joined = join(
        &engine,
        "room",
        "terminal",
        terminal_offer(terminal, &[106, 104, 105, 100]),
        &[],
    )
    .await;
    let answer = ok_sdp_text(&joined);
    assert_eq!(audio_formats(&answer), "106 105", "{answer}");
    assert!(
        answer.contains("a=fmtp:106 octet-align=1;mode-change-capability=2;max-red=220\r\n")
            || answer.contains("a=fmtp:106 mode-change-capability=2;max-red=220;octet-align=1\r\n"),
        "{answer}"
    );
}

/// The profile's codec flags edit the candidates as they do for `answer_local`: masking AMR-WB
/// seats the terminal in AMR, with the 8 kHz event that goes with it.
#[cfg(feature = "amr")]
#[tokio::test]
async fn a_masked_codec_is_not_seated() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal) = phone().await;
    let joined = join(
        &engine,
        "room",
        "terminal",
        terminal_offer(terminal, &VOLTE),
        &["codec-mask-AMR-WB"],
    )
    .await;
    let answer = ok_sdp_text(&joined);
    assert_eq!(audio_formats(&answer), "102 100", "{answer}");
    assert_eq!(
        codec_lines(&answer),
        [
            "a=rtpmap:102 AMR/8000",
            "a=fmtp:102 mode-change-capability=2;max-red=220",
            "a=rtpmap:100 telephone-event/8000",
        ],
        "{answer}"
    );
}

/// Without the `amr` feature the same offer is refused, and the reason says, codec by codec, that
/// EVS is not implemented and that AMR needs the `amr` build feature.
#[cfg(not(feature = "amr"))]
#[tokio::test]
async fn a_terminal_offer_is_refused_naming_the_missing_amr_feature() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal) = phone().await;
    let refused = join(
        &engine,
        "room",
        "terminal",
        terminal_offer(terminal, &VOLTE),
        &[],
    )
    .await;
    let reason = refusal(&refused);
    assert!(
        reason.starts_with("conference_join: no offered codec can be seated: EVS/16000 payload type 110: no decoder: unsupported: EVS transcoding is not implemented"),
        "{reason}"
    );
    for payload_type in [104, 106] {
        assert!(
            reason.contains(&format!(
                "AMR-WB/16000 payload type {payload_type}: no decoder: unsupported: AMR \
                 transcoding requires the `amr` build feature"
            )),
            "{reason}"
        );
    }
    assert!(
        reason.contains(
            "AMR/8000 payload type 102: no decoder: unsupported: AMR transcoding requires the `amr` \
             build feature"
        ),
        "{reason}"
    );
    assert!(
        !engine.conference().contains("room"),
        "no room is left behind"
    );
}

/// The first-codec rule is gone in every build: an offer led by a codec the engine cannot decode is
/// seated in the next one.
#[tokio::test]
async fn an_offer_led_by_an_undecodable_codec_is_seated_in_the_next_one() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_terminal, terminal) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP 110 8 100\r\na=rtpmap:110 EVS/16000\r\na=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:100 telephone-event/8000\r\na=ptime:20\r\n",
        ip = terminal.ip(),
        port = terminal.port(),
    );
    let answer = ok_sdp_text(&join(&engine, "room", "terminal", offer, &[]).await);
    assert_eq!(audio_formats(&answer), "8 100", "{answer}");
    assert!(!answer.contains("EVS"), "{answer}");
}

/// Strip, the keep-list and the priority order each change the seat, and a profile that withholds
/// every offered codec is refused saying so.
#[tokio::test]
async fn the_profile_codec_flags_choose_the_seat() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_caller, caller) = phone().await;
    let cases: [(&[&str], &str); 4] = [
        (&[], "0 101"),
        (&["codec-strip-PCMU"], "8 101"),
        (&["codec-except-PCMA"], "8 101"),
        (&["codec-offer-PCMA"], "8 101"),
    ];
    for (index, (flags, formats)) in cases.into_iter().enumerate() {
        let joined = join(
            &engine,
            "flags",
            &format!("caller-{index}"),
            g711_offer(caller, &[0, 8], 20),
            flags,
        )
        .await;
        assert_eq!(audio_formats(&ok_sdp_text(&joined)), formats, "{flags:?}");
    }

    let refused = join(
        &engine,
        "flags",
        "withheld",
        g711_offer(caller, &[0, 8], 20),
        &["codec-mask-PCMU", "codec-mask-PCMA"],
    )
    .await;
    assert_eq!(
        refusal(&refused),
        "conference_join: no offered codec can be seated: PCMU/8000 payload type 0: withheld by \
         the profile's codec flags; PCMA/8000 payload type 8: withheld by the profile's codec flags"
    );
}

/// A second join under a from-tag already seated is refused, and the first seat is undisturbed.
#[tokio::test]
async fn a_duplicate_from_tag_is_refused() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_caller, caller) = phone().await;
    let first =
        ok_sdp_text(&join(&engine, "room", "alice", g711_offer(caller, &[0], 20), &[]).await);
    let seated = engine
        .conference()
        .participant_at_tag("room", "alice")
        .expect("alice is seated");
    let refused = join(&engine, "room", "alice", g711_offer(caller, &[0], 20), &[]).await;
    assert_eq!(
        refusal(&refused),
        "conference_join: from-tag alice is already seated in this room"
    );
    assert_eq!(engine.conference().participant_count(), 1);
    assert_eq!(
        engine.conference().participant_at_tag("room", "alice"),
        Some(seated),
        "the first seat keeps its endpoint ({first})"
    );
}

/// The 65th seat of a room is refused as full.
#[tokio::test]
async fn a_seat_beyond_the_room_cap_is_refused() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_caller, caller) = phone().await;
    for index in 0..siphon_rtp_media::mixer::MAX_PARTICIPANTS {
        let joined = join(
            &engine,
            "full",
            &format!("seat-{index}"),
            g711_offer(caller, &[0], 20),
            &[],
        )
        .await;
        assert!(
            matches!(joined, CmdResult::Ok { .. }),
            "{index}: {joined:?}"
        );
    }
    let refused = join(
        &engine,
        "full",
        "one-too-many",
        g711_offer(caller, &[0], 20),
        &[],
    )
    .await;
    assert_eq!(
        refusal(&refused),
        "conference_join: the room is full (64 seats)"
    );
    assert_eq!(engine.conference().participant_count(), 64);
}

/// A packetization interval beyond the room's 120 ms ceiling is refused with the interval named,
/// and the room the join would have created is not left behind.
#[tokio::test]
async fn a_packetization_interval_beyond_the_ceiling_is_refused() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_caller, caller) = phone().await;
    let refused = join(
        &engine,
        "long",
        "caller",
        g711_offer(caller, &[0], 200),
        &[],
    )
    .await;
    assert_eq!(
        refusal(&refused),
        "conference_join: no offered codec can be seated: PCMU/8000 payload type 0: the room \
         cannot hold it: packetization interval 200 ms is outside 1..=120 ms"
    );
    assert!(!engine.conference().contains("long"));
    let seated = join(
        &engine,
        "long",
        "caller",
        g711_offer(caller, &[0], 120),
        &[],
    )
    .await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");
}

/// The Goertzel power of `frequency_hz` in `pcm` sampled at `rate_hz`, normalised by its length.
#[cfg(feature = "amr")]
fn tone_power(pcm: &[i16], rate_hz: u32, frequency_hz: f64) -> f64 {
    let coefficient = 2.0 * (2.0 * std::f64::consts::PI * frequency_hz / f64::from(rate_hz)).cos();
    let (mut previous, mut before_previous) = (0.0f64, 0.0f64);
    for &sample in pcm {
        let current = f64::from(sample) + coefficient * previous - before_previous;
        before_previous = previous;
        previous = current;
    }
    let power = previous * previous + before_previous * before_previous
        - coefficient * previous * before_previous;
    power / (pcm.len() as f64 * pcm.len() as f64)
}

/// One seat of the mixed-room test: its socket, the engine port it sends to, its codec and its tone.
#[cfg(feature = "amr")]
struct ToneSeat {
    socket: UdpSocket,
    engine: SocketAddr,
    codec: CodecSpec,
    tone_hz: f64,
    ssrc: u32,
}

/// Send `seat`'s tone for `frames` 20 ms frames, paced at the room tick, and decode what it hears
/// with a decoder of its own. Returns the decoded PCM at the codec's rate.
#[cfg(feature = "amr")]
async fn run_tone_seat(seat: ToneSeat, frames: u16) -> Vec<i16> {
    use siphon_rtp_media::rtp::RtpPacket;

    let mut encoder = factory::encoder_for(&seat.codec).expect("encoder");
    let mut decoder = factory::decoder_for(&seat.codec).expect("decoder");
    let rate = encoder.params().sample_rate_hz;
    let frame = encoder.frame_samples();
    let timestamp_step = seat.codec.clock_rate_hz / 50;
    let mut heard = Vec::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(20));
    let mut buffer = [0u8; 2048];
    let mut pcm = vec![0i16; 4096];
    for sequence in 0..frames {
        ticker.tick().await;
        let tone: Vec<i16> = (0..frame)
            .map(|index| {
                let time = (usize::from(sequence) * frame + index) as f64 / f64::from(rate);
                (8000.0 * (2.0 * std::f64::consts::PI * seat.tone_hz * time).sin()) as i16
            })
            .collect();
        let mut payload = [0u8; 512];
        let written = encoder.encode(&tone, &mut payload).expect("encode");
        let mut packet = vec![0x80, seat.codec.payload_type];
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(&(u32::from(sequence) * timestamp_step).to_be_bytes());
        packet.extend_from_slice(&seat.ssrc.to_be_bytes());
        packet.extend_from_slice(&payload[..written]);
        seat.socket
            .send_to(&packet, seat.engine)
            .await
            .expect("send");
        while let Ok(Ok((length, _))) =
            timeout(Duration::from_millis(1), seat.socket.recv_from(&mut buffer)).await
        {
            let Ok(received) = RtpPacket::parse(&buffer[..length]) else {
                continue;
            };
            if received.payload_type != seat.codec.payload_type {
                continue;
            }
            let samples = decoder.decode(received.payload, &mut pcm).expect("decode");
            heard.extend_from_slice(&pcm[..samples]);
        }
    }
    heard
}

/// A G.711 seat, an AMR-WB seat and an AMR seat share one room. Each sends its own tone, and each
/// hears the other two and not itself (mixed-minus-self), decoded on its own side by a decoder of its
/// own: the repository's G.711 and its AMR-WB / AMR decoders, which are bit-exact against the 3GPP
/// TS 26.174 / TS 26.074 reference vectors. The AMR-WB seat lifts the room to 16 kHz.
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mixed_room_of_g711_amr_wb_and_amr_seats_hears_each_other() {
    use crate::srtp_bridge::run_redirect_dispatcher;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    // Each seat's tone, chosen inside the narrowband passband so the G.711 seat can hear them all.
    let tones = [("g711", 500.0), ("amr-wb", 1100.0), ("amr", 1700.0)];
    let (g711_socket, g711_address) = phone().await;
    let (wideband_socket, wideband_address) = phone().await;
    let (narrowband_socket, narrowband_address) = phone().await;
    let offers = [
        g711_offer(g711_address, &[0], 20),
        terminal_offer(wideband_address, &[104, 105]),
        terminal_offer(narrowband_address, &[102, 100]),
    ];
    let mut seats = Vec::new();
    for ((socket, offer), (tag, tone_hz)) in [g711_socket, wideband_socket, narrowband_socket]
        .into_iter()
        .zip(offers)
        .zip(tones)
    {
        let answer = ok_sdp_text(&join(&engine, "mixed", tag, offer.clone(), &[]).await);
        let codec = sdp::parse(&offer)
            .expect("offer")
            .audio_codecs()
            .into_iter()
            .next()
            .expect("the offered codec");
        assert_eq!(
            audio_formats(&answer).split(' ').next(),
            Some(codec.payload_type.to_string().as_str()),
            "{tag}: {answer}"
        );
        let engine_address = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), audio_port(&answer));
        seats.push(ToneSeat {
            socket,
            engine: engine_address,
            codec,
            tone_hz,
            ssrc: 0x5EA7_0000 + seats.len() as u32,
        });
    }

    let mut tasks = Vec::new();
    for seat in seats {
        tasks.push(tokio::spawn(run_tone_seat(seat, 150)));
    }
    let mut heard = Vec::new();
    for task in tasks {
        heard.push(task.await.expect("seat task"));
    }

    let rates = [8000u32, 16_000, 8000];
    for (index, ((tag, own_hz), pcm)) in tones.iter().zip(&heard).enumerate() {
        // The last second: well past jitter-buffer priming and the room's rate change.
        let rate = rates[index];
        let window = &pcm[pcm.len().saturating_sub(rate as usize)..];
        assert!(
            window.len() >= rate as usize / 2,
            "{tag} heard {} samples",
            pcm.len()
        );
        let levels: Vec<(f64, f64)> = tones
            .iter()
            .map(|(_, frequency)| (*frequency, tone_power(window, rate, *frequency)))
            .collect();
        let loudest = levels
            .iter()
            .map(|(_, power)| *power)
            .fold(0.0f64, f64::max);
        let decibels: Vec<String> = levels
            .iter()
            .map(|(frequency, power)| {
                format!("{frequency} Hz {:.1} dB", 10.0 * (power / loudest).log10())
            })
            .collect();
        println!("{tag} received: {}", decibels.join(", "));
        for (frequency, power) in &levels {
            if frequency == own_hz {
                assert!(
                    *power < loudest / 1000.0,
                    "{tag} hears its own {own_hz} Hz tone: {decibels:?}"
                );
            } else {
                assert!(
                    *power > loudest / 10.0,
                    "{tag} does not hear the {frequency} Hz tone: {decibels:?}"
                );
            }
        }
    }
}
