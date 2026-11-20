//! Video on a WebRTC seat of a translating forwarding room (RFC 8843: the video is bundled with the
//! audio and the data channel on the seat's one ICE/DTLS transport). The SDP half is checked with a
//! libwebrtc-shaped offer; the media half runs over the UDP-loopback datapath with a real DTLS-SRTP
//! handshake against an in-process browser.

use super::webrtc_floor_channel::{engine_with_dispatcher, ROOM};
use super::*;
use siphon_rtp_dtls::DtlsCertificate;
use siphon_rtp_proto::{ForwardMedia, VideoProfile};

const ROOM_FMTP: &str = "profile-level-id=42e01f;packetization-mode=1";

fn fingerprint_line(certificate: &DtlsCertificate) -> String {
    let fingerprint = certificate.fingerprint();
    let hex = fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    format!("a=fingerprint:{} {hex}\r\n", fingerprint.hash_function)
}

/// What a libwebrtc browser offers a room: audio (PCMU here), five H.264 payload types (Baseline and
/// Constrained Baseline, both packetization modes, and a High one) each with its RTX, the transport-wide
/// congestion control extension and REMB, and a data channel, all in one BUNDLE group.
pub(super) fn libwebrtc_offer(
    address: SocketAddr,
    certificate: &DtlsCertificate,
    group: &str,
    video_direction: &str,
) -> String {
    libwebrtc_offer_with(address, certificate, group, video_direction, true)
}

/// [`libwebrtc_offer`], with or without the ICE credentials: a seat with none is keyed by the DTLS
/// handshake at once, which is what the media tests below need (no connectivity checks to run).
pub(super) fn libwebrtc_offer_with(
    address: SocketAddr,
    certificate: &DtlsCertificate,
    group: &str,
    video_direction: &str,
    ice: bool,
) -> String {
    let fingerprint = fingerprint_line(certificate);
    let ice = if ice {
        "a=ice-ufrag:brws\r\na=ice-pwd:browserpasswordbrowser01\r\na=ice-options:trickle\r\n"
    } else {
        ""
    };
    let transport = format!("{ice}{fingerprint}a=setup:actpass\r\n");
    let mut video = String::new();
    for (payload_type, fmtp) in [
        (
            96,
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f",
        ),
        (
            98,
            "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f",
        ),
        (
            100,
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
        ),
        (
            102,
            "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f",
        ),
        (
            104,
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=4d001f",
        ),
    ] {
        video.push_str(&format!(
            "a=rtpmap:{payload_type} H264/90000\r\na=rtcp-fb:{payload_type} goog-remb\r\n\
             a=rtcp-fb:{payload_type} transport-cc\r\na=rtcp-fb:{payload_type} ccm fir\r\n\
             a=rtcp-fb:{payload_type} nack\r\na=rtcp-fb:{payload_type} nack pli\r\n\
             a=fmtp:{payload_type} {fmtp}\r\n\
             a=rtpmap:{} rtx/90000\r\na=fmtp:{} apt={payload_type}\r\n",
            payload_type + 1,
            payload_type + 1,
        ));
    }
    format!(
        "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
         a=group:BUNDLE {group}\r\na=extmap-allow-mixed\r\na=msid-semantic: WMS\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\nc=IN IP4 {ip}\r\na=rtcp:9 IN IP4 0.0.0.0\r\n\
         {transport}a=mid:0\r\na=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n\
         a=sendrecv\r\na=rtcp-mux\r\na=rtpmap:0 PCMU/8000\r\n\
         m=video {port} UDP/TLS/RTP/SAVPF 96 97 98 99 100 101 102 103 104 105\r\nc=IN IP4 {ip}\r\n\
         a=rtcp:9 IN IP4 0.0.0.0\r\n{transport}a=mid:1\r\n\
         a=extmap:2 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n\
         a=extmap:3 urn:ietf:params:rtp-hdrext:toffset\r\n\
         a={video_direction}\r\na=rtcp-mux\r\na=rtcp-rsize\r\n{video}\
         m=application {port} UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 {ip}\r\n\
         {transport}a=mid:2\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n",
        port = address.port(),
        ip = address.ip(),
    )
}

pub(super) fn video_profile(fmtp: Option<&str>) -> ProfileFlags {
    ProfileFlags {
        video: Some(VideoProfile {
            fmtp: fmtp.map(str::to_string),
            bandwidth_kbps: Some(1200),
        }),
        ..ProfileFlags::default()
    }
}

pub(super) async fn join_webrtc(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    offer: String,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardJoin {
                media: ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                sdp: offer,
                profile,
            },
        )
        .await
}

/// The lines of the section whose `m=` line starts with `kind`.
fn section<'a>(text: &'a str, kind: &str) -> Vec<&'a str> {
    let mut lines = text
        .split("\r\n")
        .skip_while(|line| !line.starts_with(kind));
    let Some(first) = lines.next() else {
        return Vec::new();
    };
    std::iter::once(first)
        .chain(lines.take_while(|line| !line.starts_with("m=")))
        .collect()
}

fn streams_of(result: &CmdResult) -> Vec<String> {
    match result {
        CmdResult::Ok { streams, .. } => streams.clone(),
        other => panic!("expected Ok, got {other:?}"),
    }
}

fn declined_of(result: &CmdResult) -> Option<String> {
    match result {
        CmdResult::Ok { video_declined, .. } => video_declined.clone(),
        other => panic!("expected Ok, got {other:?}"),
    }
}

async fn browser_address() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let address = socket.local_addr().expect("addr");
    (socket, address)
}

#[tokio::test]
async fn a_libwebrtc_offer_is_answered_in_the_bundle_with_the_rooms_payload_and_the_feedback_it_serves(
) {
    let engine = engine_with_dispatcher();
    let (_socket, address) = browser_address().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    let offer = libwebrtc_offer(address, &certificate, "0 1 2", "sendrecv");
    let result = join_webrtc(&engine, "a", offer, video_profile(Some(ROOM_FMTP))).await;
    let answer = ok_sdp_text(&result);
    assert_eq!(declined_of(&result), None, "{answer}");
    assert_eq!(streams_of(&result), ["audio", "video", "floor"], "{answer}");
    let lines: Vec<&str> = answer.split("\r\n").collect();
    assert!(lines.contains(&"a=group:BUNDLE 0 1 2"), "{answer}");
    let audio = section(&answer, "m=audio");
    let video = section(&answer, "m=video");
    let audio_port = audio[0].split(' ').nth(1).expect("audio port");
    assert_eq!(
        video[0],
        format!("m=video {audio_port} UDP/TLS/RTP/SAVPF 100"),
        "one payload type, the 42e01f packetization-mode 1 one, on the audio's own port: {answer}"
    );
    assert!(video.contains(&"a=mid:1"), "{answer}");
    assert!(video.contains(&"a=rtcp-mux"), "{answer}");
    assert!(video.contains(&"a=rtpmap:100 H264/90000"), "{answer}");
    assert!(
        video.iter().any(|line| line.starts_with("a=fmtp:100 ")
            && line.contains("profile-level-id=42e01f")
            && line.contains("packetization-mode=1")),
        "{answer}"
    );
    // Only the feedback the room serves.
    let feedback: Vec<&str> = video
        .iter()
        .copied()
        .filter(|line| line.starts_with("a=rtcp-fb:"))
        .collect();
    assert_eq!(
        feedback,
        [
            "a=rtcp-fb:100 nack",
            "a=rtcp-fb:100 nack pli",
            "a=rtcp-fb:100 ccm fir"
        ]
    );
    for refused in [
        "transport-cc",
        "goog-remb",
        "a=extmap",
        "rtx",
        "a=rtcp-rsize",
    ] {
        assert!(
            !video.iter().any(|line| line.contains(refused)),
            "{refused}: {answer}"
        );
    }
    // One transport: the video repeats the audio's ICE and DTLS lines, as RFC 8843 §7.3 has it.
    for shared in ["a=ice-ufrag:", "a=ice-pwd:", "a=fingerprint:", "a=setup:"] {
        let of = |lines: &[&str]| {
            lines
                .iter()
                .find(|line| line.starts_with(shared))
                .map(|line| (*line).to_string())
        };
        assert!(of(&audio).is_some(), "{shared}: {answer}");
        assert_eq!(of(&video), of(&audio), "{shared}: {answer}");
    }
    assert_eq!(
        video[1], audio[1],
        "the audio's own connection line: {answer}"
    );
}

/// An engine whose port pool holds only the seat's own endpoint: a seat that is seated shows the
/// video took none of its own.
#[tokio::test]
async fn a_browsers_audio_feedback_is_not_answered_and_the_video_keeps_what_the_room_serves() {
    // RFC 4585 §4.2: the room sends Sender and Receiver Reports on audio and nothing else, so the
    // audio section of the answer lists no feedback.
    let engine = engine_with_dispatcher();
    let (_socket, address) = browser_address().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    let offer = libwebrtc_offer(address, &certificate, "0 1 2", "sendrecv").replacen(
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:0 PCMU/8000\r\na=rtcp-fb:0 transport-cc\r\na=rtcp-fb:0 nack\r\n",
        1,
    );
    let result = join_webrtc(&engine, "a", offer, video_profile(Some(ROOM_FMTP))).await;
    let answer = ok_sdp_text(&result);
    let audio = section(&answer, "m=audio");
    assert!(
        !audio.iter().any(|line| line.starts_with("a=rtcp-fb:")),
        "{answer}"
    );
    let video = section(&answer, "m=video");
    assert!(video.contains(&"a=rtcp-fb:100 nack pli"), "{answer}");
}

fn engine_of(endpoints: usize) -> Engine<UdpLoopbackDatapath> {
    let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(endpoints));
    tokio::spawn(crate::srtp_bridge::run_redirect_dispatcher(
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
async fn the_bundled_video_takes_no_endpoint_of_its_own() {
    let engine = engine_of(1);
    let (_socket, address) = browser_address().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    let offer = libwebrtc_offer(address, &certificate, "0 1 2", "sendrecv");
    let result = join_webrtc(&engine, "a", offer, video_profile(Some(ROOM_FMTP))).await;
    assert!(
        streams_of(&result).contains(&"video".to_string()),
        "{result:?}"
    );
    // Leaving frees the one endpoint: the same pool seats another browser.
    let left = engine
        .handle(
            CLIENT,
            Command::ForwardLeave {
                conference_id: ROOM.into(),
                from_tag: "a".into(),
            },
        )
        .await;
    assert_eq!(left, ok_empty());
    let (_other_socket, other) = browser_address().await;
    let offer = libwebrtc_offer(other, &certificate, "0 1 2", "sendrecv");
    let again = join_webrtc(&engine, "b", offer, video_profile(Some(ROOM_FMTP))).await;
    assert!(
        streams_of(&again).contains(&"video".to_string()),
        "{again:?}"
    );
}

#[tokio::test]
async fn a_video_section_on_a_transport_of_its_own_is_declined_with_the_reason() {
    let engine = engine_with_dispatcher();
    let (_socket, address) = browser_address().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    // The video is not in the audio's BUNDLE group: a transport of its own, which the room does not run.
    let offer = libwebrtc_offer(address, &certificate, "0 2", "sendrecv");
    let result = join_webrtc(&engine, "a", offer, video_profile(Some(ROOM_FMTP))).await;
    let answer = ok_sdp_text(&result);
    let reason = declined_of(&result).expect("a reason");
    assert!(
        reason.contains("BUNDLE") && reason.contains("RFC 8843"),
        "{reason}"
    );
    assert_eq!(streams_of(&result), ["audio", "floor"]);
    assert!(answer.contains("m=video 0 UDP/TLS/RTP/SAVPF"), "{answer}");
}

#[tokio::test]
async fn a_declined_video_leaves_the_bundle_group_of_the_answer() {
    // RFC 8843 §7.3.3: a section the answerer rejects is not in its group.
    let engine = engine_with_dispatcher();
    let (_socket, address) = browser_address().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    let offer = libwebrtc_offer(address, &certificate, "0 1 2", "sendrecv");
    let result = join_webrtc(
        &engine,
        "a",
        offer,
        video_profile(Some("profile-level-id=640c1f;packetization-mode=1")),
    )
    .await;
    let answer = ok_sdp_text(&result);
    assert!(declined_of(&result).is_some(), "{answer}");
    let lines: Vec<&str> = answer.split("\r\n").collect();
    assert!(lines.contains(&"a=group:BUNDLE 0 2"), "{answer}");
    assert!(answer.contains("m=video 0 UDP/TLS/RTP/SAVPF"), "{answer}");
}

#[tokio::test]
async fn without_a_video_profile_a_browsers_video_is_declined_and_leaves_the_group() {
    let engine = engine_with_dispatcher();
    let (_socket, address) = browser_address().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    let offer = libwebrtc_offer(address, &certificate, "0 1 2", "sendrecv");
    let result = join_webrtc(&engine, "a", offer, ProfileFlags::default()).await;
    let answer = ok_sdp_text(&result);
    let lines: Vec<&str> = answer.split("\r\n").collect();
    assert!(lines.contains(&"a=group:BUNDLE 0 2"), "{answer}");
    assert!(answer.contains("m=video 0 UDP/TLS/RTP/SAVPF"), "{answer}");
}

#[tokio::test]
async fn a_recvonly_browser_video_is_answered_sendonly() {
    let engine = engine_with_dispatcher();
    let (_socket, address) = browser_address().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    let offer = libwebrtc_offer(address, &certificate, "0 1 2", "recvonly");
    let result = join_webrtc(&engine, "a", offer, video_profile(Some(ROOM_FMTP))).await;
    let answer = ok_sdp_text(&result);
    let video = section(&answer, "m=video");
    assert!(video.contains(&"a=sendonly"), "{answer}");
    assert_eq!(streams_of(&result), ["audio", "video", "floor"], "{answer}");
}

#[tokio::test]
async fn node_info_advertises_forward_video_webrtc() {
    let engine = engine_with_dispatcher();
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("node_info answers a node");
    };
    assert!(node
        .features
        .iter()
        .any(|name| name == "forward_video_webrtc"));
}

fn webrtc_offer_profile(fmtp: Option<&str>) -> ProfileFlags {
    ProfileFlags {
        transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
        floor_fmtp: Some("mc_queueing;mc_priority=5;mc_granted".to_string()),
        ..video_profile(fmtp)
    }
}

async fn offer_webrtc(
    engine: &Engine<UdpLoopbackDatapath>,
    tag: &str,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::ForwardOffer {
                media: ForwardMedia::Translate,
                conference_id: ROOM.into(),
                from_tag: tag.into(),
                profile,
            },
        )
        .await
}

/// The browser's answer to the engine's offer: audio, the bundled video accepting payload type 126
/// with `fmtp` (or declining it), and the data channel.
fn browser_answer(
    address: SocketAddr,
    certificate: &DtlsCertificate,
    video: Option<&str>,
) -> String {
    let fingerprint = fingerprint_line(certificate);
    let transport = format!(
        "a=ice-ufrag:brws\r\na=ice-pwd:browserpasswordbrowser01\r\n{fingerprint}a=setup:active\r\n"
    );
    let video_section = match video {
        Some(fmtp) => format!(
            "m=video 9 UDP/TLS/RTP/SAVPF 126\r\nc=IN IP4 0.0.0.0\r\n{transport}a=mid:2\r\n\
             a=rtpmap:126 H264/90000\r\na=fmtp:126 {fmtp}\r\na=rtcp-fb:126 nack\r\n\
             a=rtcp-fb:126 nack pli\r\na=rtcp-fb:126 ccm fir\r\na=sendrecv\r\na=rtcp-mux\r\n"
        ),
        None => "m=video 0 UDP/TLS/RTP/SAVPF 126\r\nc=IN IP4 0.0.0.0\r\na=mid:2\r\n".to_string(),
    };
    format!(
        "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0 1 2\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\nc=IN IP4 {ip}\r\n{transport}a=mid:0\r\n\
         a=rtpmap:0 PCMU/8000\r\na=sendrecv\r\na=rtcp-mux\r\n\
         m=application {port} UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 {ip}\r\n{transport}\
         a=mid:1\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n{video_section}",
        port = address.port(),
        ip = address.ip(),
    )
}

#[tokio::test]
async fn a_webrtc_forward_offer_with_video_bundles_it_and_its_answer_seats_the_video() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let offered = offer_webrtc(&engine, "a", webrtc_offer_profile(Some(ROOM_FMTP))).await;
    let offer = ok_sdp_text(&offered);
    assert_eq!(declined_of(&offered), None, "{offer}");
    let lines: Vec<&str> = offer.split("\r\n").collect();
    assert!(lines.contains(&"a=group:BUNDLE 0 1 2"), "{offer}");
    let audio = section(&offer, "m=audio");
    let video = section(&offer, "m=video");
    let audio_port = audio[0].split(' ').nth(1).expect("audio port");
    assert_eq!(
        video[0],
        format!("m=video {audio_port} UDP/TLS/RTP/SAVPF 126"),
        "{offer}"
    );
    for expected in [
        "a=mid:2",
        "a=rtcp-mux",
        "a=rtcp-fb:126 nack",
        "a=rtcp-fb:126 nack pli",
        "a=rtcp-fb:126 ccm fir",
        "a=fmtp:126 profile-level-id=42e01f;packetization-mode=1",
    ] {
        assert!(video.contains(&expected), "{expected}: {offer}");
    }
    // The browser accepts the video; the seat is seated with it.
    let (_socket, address) = browser_address().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    let answered = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                sdp: browser_answer(address, &certificate, Some(ROOM_FMTP)),
                received_from: None,
            },
        )
        .await;
    assert_eq!(
        streams_of(&answered),
        ["audio", "video", "floor"],
        "{answered:?}"
    );
    assert_eq!(declined_of(&answered), None);
}

#[tokio::test]
async fn a_browser_that_declines_the_offered_video_is_seated_audio_only_with_the_reason() {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    offer_webrtc(&engine, "a", webrtc_offer_profile(Some(ROOM_FMTP))).await;
    let (_socket, address) = browser_address().await;
    let certificate = DtlsCertificate::generate().expect("certificate");
    let answered = engine
        .handle(
            CLIENT,
            Command::ForwardAnswer {
                conference_id: ROOM.into(),
                from_tag: "a".into(),
                sdp: browser_answer(address, &certificate, None),
                received_from: None,
            },
        )
        .await;
    assert_eq!(streams_of(&answered), ["audio", "floor"], "{answered:?}");
    assert!(declined_of(&answered)
        .expect("a reason")
        .contains("declined"));
}

// ---- media: a real DTLS-SRTP handshake and SRTP video over the loopback datapath ----

use super::webrtc_floor_channel::{NEGATIVE, SHORT};
use siphon_rtp_dtls::{DtlsEvent, DtlsRole, DtlsSession};
use siphon_rtp_media::rtcp;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket};
use siphon_rtp_srtp::leg::{PacketKind, SecureLeg};
use std::time::Instant;

/// An in-process browser: a DTLS session on a loopback socket that, once keyed, protects and
/// unprotects RTP and RTCP with the keys the handshake exported (RFC 5764 §4.2).
struct SrtpBrowser {
    socket: Arc<UdpSocket>,
    engine: SocketAddr,
    leg: SecureLeg,
    media: flume::Receiver<Vec<u8>>,
    task: tokio::task::JoinHandle<()>,
}

impl SrtpBrowser {
    async fn start(
        socket: Arc<UdpSocket>,
        engine: SocketAddr,
        certificate: DtlsCertificate,
        engine_fingerprint: &sdp::Fingerprint,
        role: DtlsRole,
    ) -> Self {
        let expected = siphon_rtp_dtls::Fingerprint::new(
            engine_fingerprint.hash_function.clone(),
            engine_fingerprint.bytes.clone(),
        );
        let (keyed, keyed_rx) = flume::bounded(1);
        let (media_tx, media) = flume::unbounded();
        let task_socket = socket.clone();
        let task = tokio::spawn(async move {
            let socket = task_socket;
            let mut session =
                DtlsSession::new(&certificate, role, expected, Duration::from_millis(200))
                    .expect("browser session");
            session.start(Instant::now()).expect("first flight");
            let mut buffer = [0u8; 2048];
            loop {
                while let Some(record) = session.poll_transmit() {
                    socket.send_to(&record, engine).await.expect("browser send");
                }
                let wait = session
                    .poll_timeout()
                    .map_or(Duration::from_secs(3600), |at| {
                        at.saturating_duration_since(Instant::now())
                    });
                tokio::select! {
                    received = socket.recv_from(&mut buffer) => {
                        let Ok((length, _)) = received else { return };
                        match buffer[0] {
                            // RFC 7983 §7: a DTLS record.
                            20..=63 => {
                                let Ok(events) = session.handle_datagram(Instant::now(), &buffer[..length]) else {
                                    return;
                                };
                                for event in events {
                                    if matches!(event, DtlsEvent::Keyed) {
                                        if let Some(keying) = session.keying() {
                                            let _ = keyed.send(keying.to_secure_leg());
                                        }
                                    }
                                }
                            }
                            // RFC 7983 §7: RTP or RTCP.
                            128..=191 => {
                                let _ = media_tx.send(buffer[..length].to_vec());
                            }
                            _ => {}
                        }
                    }
                    () = tokio::time::sleep(wait) => {
                        let _ = session.handle_timeout(Instant::now());
                    }
                }
            }
        });
        let leg = tokio::time::timeout(SHORT, keyed_rx.recv_async())
            .await
            .expect("the handshake keys in time")
            .expect("the browser task is alive");
        Self {
            socket,
            engine,
            leg,
            media,
            task,
        }
    }

    /// Protect `clear` (RTP or RTCP) and send it to the engine.
    async fn send(&mut self, clear: &[u8]) {
        let mut wire = Vec::new();
        self.leg.protect(clear, &mut wire).expect("protect");
        self.socket.send_to(&wire, self.engine).await.expect("send");
    }

    /// The next datagram of `kind` the engine sent, unprotected; the others are skipped.
    async fn receive(&mut self, kind: PacketKind, window: Duration) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + window;
        while let Ok(Ok(wire)) = tokio::time::timeout_at(deadline, self.media.recv_async()).await {
            let mut clear = Vec::new();
            match self.leg.unprotect(&wire, &mut clear) {
                Ok(found) if found == kind => return Some(clear),
                Ok(_) => {}
                Err(error) => panic!("what the engine sent does not unprotect: {error}"),
            }
        }
        None
    }
}

impl Drop for SrtpBrowser {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The engine's own video datagrams are never RTCP: skip RTCP and hand back the first RTP.
async fn next_video(browser: &mut SrtpBrowser, window: Duration) -> Option<Vec<u8>> {
    browser.receive(PacketKind::Rtp, window).await
}

/// A joined browser: its socket, handshake done.
async fn joined_browser(engine: &Engine<UdpLoopbackDatapath>, tag: &str) -> (SrtpBrowser, String) {
    let socket = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind"),
    );
    let address = socket.local_addr().expect("addr");
    let certificate = DtlsCertificate::generate().expect("certificate");
    let offer = libwebrtc_offer_with(address, &certificate, "0 1 2", "sendrecv", false);
    let answer =
        ok_sdp_text(&join_webrtc(engine, tag, offer, video_profile(Some(ROOM_FMTP))).await);
    let parsed = sdp::parse(&answer).expect("answer");
    let fingerprint = parsed.fingerprint.clone().expect("engine fingerprint");
    // The browser offered `actpass` and the engine answered `active`: the engine is the DTLS client,
    // so the browser is the server.
    let browser = SrtpBrowser::start(
        socket,
        parsed.remote_rtp,
        certificate,
        &fingerprint,
        DtlsRole::Server,
    )
    .await;
    // The handshake keyed the browser's side; the engine's room is keyed a moment later.
    tokio::time::sleep(Duration::from_millis(150)).await;
    (browser, answer)
}

fn rtp_packet(
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    payload: &[u8],
) -> Vec<u8> {
    let header = RtpHeader {
        marker: false,
        payload_type,
        sequence,
        timestamp,
        ssrc,
    };
    let mut buffer = vec![0u8; 12 + payload.len()];
    write_packet(&header, payload, &mut buffer).expect("write");
    buffer
}

async fn set_room_source(engine: &Engine<UdpLoopbackDatapath>, tag: &str) {
    let result = engine
        .handle(
            CLIENT,
            Command::ForwardSetSource {
                conference_id: ROOM.into(),
                from_tag: Some(tag.to_string()),
            },
        )
        .await;
    assert_eq!(result, ok_empty());
}

const IDR_FU_A: [u8; 5] = [0x7C, 0x85, 1, 2, 3];
const SLICE: [u8; 3] = [0x41, 0x9A, 0x00];

#[tokio::test]
async fn video_goes_between_two_browsers_as_srtp_after_a_pli_and_the_talkers_idr() {
    let engine = engine_with_dispatcher();
    let events = engine.register_client(CLIENT);
    let (mut talker, _) = joined_browser(&engine, "a").await;
    let (mut listener, _) = joined_browser(&engine, "b").await;
    // The talker has sent some video (the room learns the SSRC it must ask a keyframe of).
    talker
        .send(&rtp_packet(100, 1, 9_000, 0xA0A0_A0A0, &SLICE))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    set_room_source(&engine, "a").await;
    // SRTCP to the talker: a PLI about its stream, from the stream the room sends it.
    let request = loop {
        let datagram = talker
            .receive(PacketKind::Rtcp, SHORT)
            .await
            .expect("a keyframe request as SRTCP");
        if rtcp::feedback_packets(&datagram).any(|item| item.is_ok()) {
            break datagram;
        }
    };
    let feedback: Vec<_> = rtcp::feedback_packets(&request)
        .map(|item| item.expect("well formed"))
        .collect();
    assert!(
        matches!(
            feedback[..],
            [rtcp::Feedback::Pli {
                media_ssrc: 0xA0A0_A0A0,
                ..
            }]
        ),
        "{feedback:?}"
    );
    // A picture before the keyframe is held back from the listener; the IDR starts it.
    talker
        .send(&rtp_packet(100, 2, 12_000, 0xA0A0_A0A0, &SLICE))
        .await;
    assert!(next_video(&mut listener, NEGATIVE).await.is_none());
    talker
        .send(&rtp_packet(100, 3, 15_000, 0xA0A0_A0A0, &IDR_FU_A))
        .await;
    let heard = next_video(&mut listener, SHORT)
        .await
        .expect("video as SRTP");
    let packet = RtpPacket::parse(&heard).expect("rtp");
    assert_eq!(
        packet.payload_type, 100,
        "the listener's own number for the room's format"
    );
    assert_ne!(packet.ssrc, 0xA0A0_A0A0, "the listener's own SSRC");
    assert_eq!(packet.payload, IDR_FU_A);
    assert!(
        next_video(&mut talker, NEGATIVE).await.is_none(),
        "the source never hears itself"
    );
    // The keyframe event of the switch.
    let deadline = tokio::time::Instant::now() + SHORT;
    let mut reported = false;
    while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, events.recv_async()).await {
        if let Event::ForwardKeyframe {
            from_tag,
            timed_out,
            ..
        } = event
        {
            assert_eq!((from_tag.as_str(), timed_out), ("a", false));
            reported = true;
            break;
        }
    }
    assert!(reported, "no forward_keyframe event");
}

/// A plain RTP/AVPF phone with a video socket of its own, in the room's format.
struct PlainPhone {
    video: UdpSocket,
    engine_video: SocketAddr,
    _audio: UdpSocket,
}

async fn plain_phone(engine: &Engine<UdpLoopbackDatapath>, tag: &str) -> PlainPhone {
    let (audio, audio_address) = phone().await;
    let (video, video_address) = phone().await;
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {audio_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         m=video {video_port} RTP/AVPF 97\r\na=rtpmap:97 H264/90000\r\n\
         a=fmtp:97 {ROOM_FMTP}\r\na=rtcp-fb:97 nack\r\na=rtcp-fb:97 nack pli\r\na=rtcp-fb:97 ccm fir\r\n\
         a=sendrecv\r\na=rtcp-mux\r\n",
        ip = audio_address.ip(),
        audio_port = audio_address.port(),
        video_port = video_address.port(),
    );
    let answer =
        ok_sdp_text(&join_webrtc(engine, tag, offer, video_profile(Some(ROOM_FMTP))).await);
    let engine_video = sdp::video::parse_video(&answer)
        .expect("a live video section")
        .remote;
    PlainPhone {
        video,
        engine_video,
        _audio: audio,
    }
}

async fn plain_receive(socket: &UdpSocket, window: Duration) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + window;
    let mut buffer = [0u8; 2048];
    while let Ok(Ok((length, _))) =
        tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await
    {
        if length >= 2 && !(64..=95).contains(&(buffer[1] & 0x7f)) {
            return Some(buffer[..length].to_vec());
        }
    }
    None
}

#[tokio::test]
async fn video_from_a_plain_phone_reaches_a_browser_as_srtp_and_a_browsers_reaches_the_phone_in_clear(
) {
    let engine = engine_with_dispatcher();
    let _events = engine.register_client(CLIENT);
    let phone = plain_phone(&engine, "phone").await;
    let (mut browser, _) = joined_browser(&engine, "browser").await;
    // Plain source to browser receiver.
    set_room_source(&engine, "phone").await;
    phone
        .video
        .send_to(
            &rtp_packet(97, 10, 90_000, 0xB1B1_B1B1, &IDR_FU_A),
            phone.engine_video,
        )
        .await
        .expect("send");
    let heard = next_video(&mut browser, SHORT)
        .await
        .expect("video as SRTP");
    let packet = RtpPacket::parse(&heard).expect("rtp");
    assert_eq!(packet.payload_type, 100);
    assert_eq!(packet.payload, IDR_FU_A);
    // Browser source to plain receiver: the phone is sent the clear RTP in its own payload type.
    set_room_source(&engine, "browser").await;
    browser
        .send(&rtp_packet(100, 1, 9_000, 0xC2C2_C2C2, &IDR_FU_A))
        .await;
    let heard = plain_receive(&phone.video, SHORT)
        .await
        .expect("clear video");
    let packet = RtpPacket::parse(&heard).expect("rtp");
    assert_eq!(packet.payload_type, 97, "the phone's own number");
    assert_ne!(packet.ssrc, 0xC2C2_C2C2);
    assert_eq!(packet.payload, IDR_FU_A);
}
