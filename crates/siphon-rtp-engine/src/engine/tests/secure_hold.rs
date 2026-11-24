#![cfg(test)]

//! Holding a call on a crypto bridge in the decoding media actor and releasing it back, end to end on
//! real loopback sockets with the redirect dispatcher live.
//!
//! Every scenario drives the same cycle: media crosses on the bridge, the call is held
//! ([`PromotionReason::WsSplit`]) and media crosses through the decoding actor, the hold is released
//! and media crosses on the bridge again. Throughout, each party is a test phone holding its **own**
//! SRTP context, built from the key material and never from the engine's objects, so a hand-over that
//! restarted a master key, a rollover counter, a replay window or the SRTCP index fails to decrypt
//! here, and a hand-over that changed the SSRC or broke the sequence continuity shows in what the
//! phone receives (RFC 3711 §3.3.1, RFC 3550 §5.1).

use super::*;
use crate::media_pipeline::MediaControl;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_dtls::DtlsCertificate;

const LOUD: u8 = 0x00;
/// µ-law encoding of PCM zero: what a silenced egress carries.
const SILENT: u8 = 0xFF;

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

/// One RTP packet a phone heard.
#[derive(Clone, Debug)]
struct HeardPacket {
    ssrc: u32,
    sequence: u16,
    timestamp: u32,
    payload: Vec<u8>,
}

/// What a phone heard in a window.
#[derive(Default, Debug)]
struct Heard {
    media: Vec<HeardPacket>,
    /// RTCP datagrams as they arrived (still sealed on a secure leg).
    rtcp: Vec<Vec<u8>>,
    /// Datagrams that failed to authenticate or decrypt under the phone's own context.
    rejected: usize,
}

impl Heard {
    fn absorb(&mut self, other: Heard) {
        self.media.extend(other.media);
        self.rtcp.extend(other.rtcp);
        self.rejected += other.rejected;
    }
}

/// A test phone: a socket, the engine address it talks to, its own SRTP context if its leg is secure,
/// and the stream it sends.
struct Phone {
    socket: Arc<UdpSocket>,
    engine: SocketAddr,
    leg: Option<SecureLeg>,
    ssrc: u32,
    next_sequence: u16,
    /// The last datagram this phone sent, for a test that replays it.
    last_sent: Vec<u8>,
    /// Whether a sealed RTCP datagram ends in an RFC 3711 §3.4 index (HMAC-SHA1-80 suites).
    sdes_suite: bool,
}

impl Phone {
    fn new(socket: Arc<UdpSocket>, engine: SocketAddr, leg: Option<SecureLeg>, ssrc: u32) -> Self {
        Self {
            socket,
            engine,
            leg,
            ssrc,
            next_sequence: 1000,
            last_sent: Vec::new(),
            sdes_suite: false,
        }
    }

    fn seal(&mut self, packet: &[u8]) -> Vec<u8> {
        match self.leg.as_mut() {
            Some(leg) => {
                let mut sealed = Vec::new();
                leg.protect(packet, &mut sealed).expect("phone protects");
                sealed
            }
            None => packet.to_vec(),
        }
    }

    /// Send one G.711 frame carrying `payload_byte`, `skip` sequence numbers after the last one (an
    /// upstream loss).
    async fn send_frame(&mut self, payload_byte: u8, skip: u16) {
        self.next_sequence = self.next_sequence.wrapping_add(skip);
        let packet = g711_rtp(0, self.next_sequence, self.ssrc, payload_byte);
        self.next_sequence = self.next_sequence.wrapping_add(1);
        let sealed = self.seal(&packet);
        self.socket
            .send_to(&sealed, self.engine)
            .await
            .expect("phone sends");
        self.last_sent = sealed;
    }

    /// Send a minimal RTCP sender report from this phone's SSRC.
    async fn send_report(&mut self) {
        let mut report = vec![0x80, 200, 0x00, 0x06];
        report.extend_from_slice(&self.ssrc.to_be_bytes());
        report.extend_from_slice(&[0u8; 20]);
        let sealed = self.seal(&report);
        self.socket
            .send_to(&sealed, self.engine)
            .await
            .expect("phone sends a report");
    }

    /// Everything that reaches this phone within `window`, decrypted under its own context.
    async fn listen(&mut self, window: Duration) -> Heard {
        let mut heard = Heard::default();
        let mut buffer = [0u8; 2048];
        let deadline = tokio::time::Instant::now() + window;
        while let Ok(Ok((len, _))) =
            tokio::time::timeout_at(deadline, self.socket.recv_from(&mut buffer)).await
        {
            let datagram = &buffer[..len];
            // RFC 7983 §7: RTP and RTCP are 128..=191; STUN and DTLS are somebody else's.
            if !(128..=191).contains(&datagram[0]) {
                continue;
            }
            let rtcp = len >= 2 && (64..=95).contains(&(datagram[1] & 0x7f));
            let plain = match self.leg.as_mut() {
                Some(leg) => {
                    let mut plain = Vec::new();
                    if leg.unprotect(datagram, &mut plain).is_err() {
                        heard.rejected += 1;
                        continue;
                    }
                    plain
                }
                None => datagram.to_vec(),
            };
            if rtcp {
                heard.rtcp.push(datagram.to_vec());
            } else if plain.len() >= 12 {
                heard.media.push(HeardPacket {
                    ssrc: u32::from_be_bytes([plain[8], plain[9], plain[10], plain[11]]),
                    sequence: u16::from_be_bytes([plain[2], plain[3]]),
                    timestamp: u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]),
                    payload: plain[12..].to_vec(),
                });
            }
        }
        heard
    }
}

/// The SRTCP index of a sealed report on an HMAC-SHA1-80 leg: the 31 bits before the 10-byte tag.
fn srtcp_index(sealed: &[u8]) -> u32 {
    let at = sealed.len() - 14;
    u32::from_be_bytes([sealed[at], sealed[at + 1], sealed[at + 2], sealed[at + 3]]) & 0x7fff_ffff
}

/// A call up on one crypto bridge kind (or none, for the plain relay), its two phones and what it
/// resolves to.
struct Rig {
    engine: Engine<UdpLoopbackDatapath>,
    call_id: &'static str,
    a: Phone,
    b: Phone,
    original: PipelineKind,
    held: PipelineKind,
    /// What a re-offer of the call sends, where the scenario has one.
    reoffer: Option<Reoffer>,
}

/// A re-offer from A, B's answer to it, and what a new DTLS association would be answered with.
struct Reoffer {
    sdp: String,
    profile: ProfileFlags,
    answer: String,
    /// B's address.
    far_addr: SocketAddr,
}

impl Rig {
    fn kind(&self) -> PipelineKind {
        self.engine.calls.get(self.call_id).expect("call").pipeline
    }

    /// One frame each way, `skip` sequence numbers lost first, then listen for a frame time.
    async fn exchange(&mut self, loud: u8, skip: u16) -> (Heard, Heard) {
        self.a.send_frame(loud, skip).await;
        self.b.send_frame(loud, skip).await;
        tokio::time::sleep(Duration::from_millis(12)).await;
        let heard_a = self.a.listen(Duration::from_millis(8)).await;
        let heard_b = self.b.listen(Duration::from_millis(8)).await;
        (heard_a, heard_b)
    }

    async fn run(&mut self, frames: usize, loud: u8, skip_at: Option<usize>) -> (Heard, Heard) {
        let (mut at_a, mut at_b) = (Heard::default(), Heard::default());
        for frame in 0..frames {
            let skip = if skip_at == Some(frame) { 7 } else { 0 };
            let (heard_a, heard_b) = self.exchange(loud, skip).await;
            at_a.absorb(heard_a);
            at_b.absorb(heard_b);
        }
        (at_a, at_b)
    }

    /// Frames each way until both phones have heard one: the window between a handshake finishing
    /// and the engine installing its key.
    async fn warm_up(&mut self) {
        for _ in 0..60 {
            let (heard_a, heard_b) = self.exchange(LOUD, 0).await;
            if !heard_a.media.is_empty() && !heard_b.media.is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        panic!("the call never relayed media both ways");
    }

    async fn hold(&self) -> Result<(), String> {
        self.engine
            .hold_in_userspace(
                self.call_id,
                PromotionReason::WsSplit,
                PromoteMode::Processing,
            )
            .await
    }

    async fn release(&self) {
        self.engine
            .release_userspace_hold(self.call_id, PromotionReason::WsSplit)
            .await;
    }
}

/// `heard` is one unbroken stream of `ssrc`: the sequence number rises by one on every packet, the
/// timestamp moves forward by whole 20 ms frames, and nothing failed to decrypt.
fn assert_one_stream(heard: &Heard, ssrc: u32, who: &str) {
    assert_eq!(heard.rejected, 0, "{who}: every datagram decrypts");
    assert!(heard.media.len() >= 8, "{who}: heard media: {heard:?}");
    for pair in heard.media.windows(2) {
        assert_eq!(pair[1].ssrc, ssrc, "{who}: one SSRC throughout");
        assert_eq!(
            pair[1].sequence,
            pair[0].sequence.wrapping_add(1),
            "{who}: the sequence number never jumps: {pair:?}"
        );
        let step = pair[1].timestamp.wrapping_sub(pair[0].timestamp);
        assert!(
            step > 0 && step % 160 == 0 && step <= 160 * 20,
            "{who}: the timestamp moves forward by whole frames: {pair:?}"
        );
    }
    assert_eq!(heard.media[0].ssrc, ssrc, "{who}: the stream's SSRC");
}

fn only_silence(heard: &Heard) -> bool {
    !heard.media.is_empty()
        && heard
            .media
            .iter()
            .all(|packet| packet.payload.iter().all(|byte| *byte == SILENT))
}

/// The whole cycle, against one rig.
async fn assert_hold_cycle(mut rig: Rig) {
    rig.warm_up().await;
    // Reports cross before the hold, under the leg's SRTCP index.
    let mut reports_a = Vec::new();
    let mut reports_b = Vec::new();

    // ---- before: the bridge relays verbatim ----------------------------------------------------
    let (mut at_a, mut at_b) = rig.run(10, LOUD, None).await;
    rig.a.send_report().await;
    rig.b.send_report().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (report_a, report_b) = (
        rig.a.listen(Duration::from_millis(20)).await,
        rig.b.listen(Duration::from_millis(20)).await,
    );
    reports_a.extend(report_a.rtcp.clone());
    reports_b.extend(report_b.rtcp.clone());
    assert_eq!(report_a.rejected + report_b.rejected, 0);
    at_a.absorb(report_a);
    at_b.absorb(report_b);
    assert_eq!(rig.kind(), rig.original, "starts on its bridge kind");

    // ---- hold ----------------------------------------------------------------------------------
    rig.hold().await.expect("the call is held");
    assert_eq!(rig.kind(), rig.held, "held in the decoding actor");
    assert!(
        rig.engine.media.is_media_call(rig.call_id),
        "an actor now carries the call"
    );
    let (near_rtp, far_rtp) = {
        let call = rig.engine.calls.get(rig.call_id).expect("call");
        (call.near.rtp.id, call.far_leg().rtp.id)
    };
    match rig.original {
        PipelineKind::Srtp | PipelineKind::SrtpOfferer | PipelineKind::SrtpTranscrypt => assert!(
            !rig.engine.bridge.owns(near_rtp) && !rig.engine.bridge.owns(far_rtp),
            "the SDES bridge let go of both endpoints"
        ),
        // The DTLS leg keeps its association and its demux in the bridge; the plain side is the actor's.
        PipelineKind::Dtls => {
            assert!(!rig.engine.bridge.owns(near_rtp) && rig.engine.bridge.owns(far_rtp))
        }
        PipelineKind::DtlsOfferer => {
            assert!(rig.engine.bridge.owns(near_rtp) && !rig.engine.bridge.owns(far_rtp));
        }
        _ => {}
    }

    // Audio crosses decoded, with upstream loss in the middle: the stream stays contiguous.
    let (held_a, held_b) = rig.run(12, LOUD, Some(6)).await;
    at_a.absorb(held_a);
    at_b.absorb(held_b);
    // Reports cross through the actor, under the same SRTCP index sequence.
    rig.a.send_report().await;
    rig.b.send_report().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (report_a, report_b) = (
        rig.a.listen(Duration::from_millis(20)).await,
        rig.b.listen(Duration::from_millis(20)).await,
    );
    reports_a.extend(report_a.rtcp.clone());
    reports_b.extend(report_b.rtcp.clone());
    assert_eq!(report_a.rejected + report_b.rejected, 0);
    at_a.absorb(report_a);
    at_b.absorb(report_b);

    // The audio goes through a decoder and an encoder: silencing the egress silences it.
    rig.engine
        .media
        .control(rig.call_id, MediaControl::Silence(true));
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (silenced_a, silenced_b) = rig.run(6, LOUD, None).await;
    assert!(
        only_silence(&silenced_a) && only_silence(&silenced_b),
        "a decoded path can be silenced; a verbatim relay cannot: {silenced_a:?} {silenced_b:?}"
    );
    at_a.absorb(silenced_a);
    at_b.absorb(silenced_b);
    rig.engine
        .media
        .control(rig.call_id, MediaControl::Silence(false));
    tokio::time::sleep(Duration::from_millis(20)).await;

    // A stranger is still dropped while held: a valid packet of another SSRC from another address.
    let stranger = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 9), 0))
        .await
        .expect("bind stranger");
    let injected = g711_rtp(0, 60_000, 0xBAD0_BAD0, LOUD);
    let sealed = rig.a.seal(&injected);
    stranger
        .send_to(&sealed, rig.a.engine)
        .await
        .expect("stranger sends");
    let sealed = rig.b.seal(&injected);
    stranger
        .send_to(&sealed, rig.b.engine)
        .await
        .expect("stranger sends");
    let (during_a, during_b) = rig.run(4, LOUD, None).await;
    assert!(
        during_a
            .media
            .iter()
            .chain(during_b.media.iter())
            .all(|packet| packet.ssrc != 0xBAD0_BAD0),
        "a source nobody signalled reaches neither party while the call is held"
    );
    at_a.absorb(during_a);
    at_b.absorb(during_b);

    // ---- release -------------------------------------------------------------------------------
    rig.release().await;
    assert_eq!(rig.kind(), rig.original, "back on its bridge kind");
    assert!(
        !rig.engine.media.is_media_call(rig.call_id),
        "the actor is gone"
    );
    let (after_a, after_b) = rig.run(12, LOUD, None).await;
    assert!(
        !only_silence(&after_a) && !only_silence(&after_b),
        "the bridge relays what was sent"
    );
    at_a.absorb(after_a);
    at_b.absorb(after_b);
    rig.a.send_report().await;
    rig.b.send_report().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (report_a, report_b) = (
        rig.a.listen(Duration::from_millis(20)).await,
        rig.b.listen(Duration::from_millis(20)).await,
    );
    reports_a.extend(report_a.rtcp.clone());
    reports_b.extend(report_b.rtcp.clone());
    assert_eq!(report_a.rejected + report_b.rejected, 0);
    at_a.absorb(report_a);
    at_b.absorb(report_b);

    // ---- the stream each party received across both hand-overs ---------------------------------
    // A plain relay cannot renumber a stream, so its actor numbers its own and the carrier's returns
    // verbatim (RFC 3550 §8.2); every crypto bridge keeps one SSRC and one sequence throughout.
    if rig.original == PipelineKind::Passthrough {
        assert_eq!(at_a.rejected + at_b.rejected, 0);
        assert!(at_b.media.len() > 20 && at_a.media.len() > 20);
        let last_b = at_b.media.last().expect("heard after release");
        assert_eq!(
            last_b.ssrc, rig.a.ssrc,
            "released: the carrier's own SSRC again"
        );
        return;
    }
    assert_one_stream(&at_b, rig.a.ssrc, "B hears A");
    assert_one_stream(&at_a, rig.b.ssrc, "A hears B");

    // SRTCP: every report decrypted under the receiver's own context (a replayed or restarted index
    // would not), and on an SDES leg the index counts up by one across both hand-overs.
    for (reports, phone, who) in [(&reports_a, &rig.a, "A"), (&reports_b, &rig.b, "B")] {
        assert!(reports.len() >= 3, "{who} heard a report in each phase");
        if phone.leg.is_some() && phone.sdes_suite {
            for pair in reports.windows(2) {
                assert_eq!(
                    srtcp_index(&pair[1]),
                    srtcp_index(&pair[0]) + 1,
                    "{who}: the SRTCP index continues across the hand-overs"
                );
            }
        }
    }
}

// ---- rigs ----------------------------------------------------------------------------------

fn sdes_key() -> CryptoAttribute {
    CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key")
}

async fn plain_rig() -> Rig {
    let engine = engine_with_dispatcher();
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offered = offer_from_a(
        &engine,
        "hold-plain",
        sdp_for(addr_a, true),
        Default::default(),
    )
    .await;
    let answered = answer_from_b(
        &engine,
        "hold-plain",
        sdp_for(addr_b, true),
        Default::default(),
    )
    .await;
    Rig {
        engine,
        call_id: "hold-plain",
        a: Phone::new(Arc::new(phone_a), answered.remote_rtp, None, 0x0A0A_0A0A),
        b: Phone::new(Arc::new(phone_b), offered.remote_rtp, None, 0x0B0B_0B0B),
        original: PipelineKind::Passthrough,
        held: PipelineKind::Media,
        reoffer: None,
    }
}

/// A plain A and an SDES B (`PipelineKind::Srtp`).
async fn srtp_rig() -> Rig {
    srtp_rig_with(&[]).await
}

/// [`srtp_rig`] with profile `flags` on the offer and the answer (`symmetric` opens A's gate).
async fn srtp_rig_with(flags: &[&str]) -> Rig {
    let flags: Vec<String> = flags.iter().map(|flag| (*flag).to_string()).collect();
    let engine = engine_with_dispatcher();
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "hold-srtp".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    flags: flags.clone(),
                    ..Default::default()
                },
            },
        )
        .await;
    let offered = sdp::parse(&ok_sdp_text(&offered)).expect("offer");
    let engine_key = *offered.crypto.first().expect("engine key toward B");
    let key_b = sdes_key();
    let answered = answer_from_b(
        &engine,
        "hold-srtp",
        savp_answer_sdp(addr_b, &key_b),
        ProfileFlags {
            flags,
            ..Default::default()
        },
    )
    .await;
    let mut b = Phone::new(
        Arc::new(phone_b),
        offered.remote_rtp,
        Some(SecureLeg::new(&key_b.key, &engine_key.key)),
        0x0B0B_0B0B,
    );
    b.sdes_suite = true;
    Rig {
        engine,
        call_id: "hold-srtp",
        a: Phone::new(Arc::new(phone_a), answered.remote_rtp, None, 0x0A0A_0A0A),
        b,
        original: PipelineKind::Srtp,
        held: PipelineKind::SrtpMedia,
        reoffer: Some(Reoffer {
            sdp: sdp_for(addr_a, true),
            profile: ProfileFlags {
                transport_protocol: Some("RTP/SAVP".into()),
                ..Default::default()
            },
            answer: savp_answer_sdp(addr_b, &key_b),
            far_addr: addr_b,
        }),
    }
}

/// An SDES A and a plain B (`PipelineKind::SrtpOfferer`).
async fn srtp_offerer_rig() -> Rig {
    let engine = engine_with_dispatcher();
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let key_a = sdes_key();
    let offered = offer_from_a(
        &engine,
        "hold-offerer",
        sdes_offerer_sdp(addr_a, &key_a),
        Default::default(),
    )
    .await;
    let answered = answer_from_b(
        &engine,
        "hold-offerer",
        sdp_for(addr_b, true),
        Default::default(),
    )
    .await;
    let engine_key = *answered.crypto.first().expect("engine key toward A");
    let mut a = Phone::new(
        Arc::new(phone_a),
        answered.remote_rtp,
        Some(SecureLeg::new(&key_a.key, &engine_key.key)),
        0x0A0A_0A0A,
    );
    a.sdes_suite = true;
    Rig {
        engine,
        call_id: "hold-offerer",
        a,
        b: Phone::new(Arc::new(phone_b), offered.remote_rtp, None, 0x0B0B_0B0B),
        original: PipelineKind::SrtpOfferer,
        held: PipelineKind::SrtpOffererMedia,
        reoffer: None,
    }
}

/// An SDES A and an SDES B under different keys (`PipelineKind::SrtpTranscrypt`).
async fn srtp_transcrypt_rig() -> Rig {
    let engine = engine_with_dispatcher();
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let key_a = sdes_key();
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "hold-transcrypt".into(),
                from_tag: "a".into(),
                sdp: sdes_offerer_sdp(addr_a, &key_a),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offered = sdp::parse(&ok_sdp_text(&offered)).expect("offer");
    let engine_key_b = *offered.crypto.first().expect("engine key toward B");
    let key_b = sdes_key();
    let answered = answer_from_b(
        &engine,
        "hold-transcrypt",
        savp_answer_sdp(addr_b, &key_b),
        Default::default(),
    )
    .await;
    let engine_key_a = *answered.crypto.first().expect("engine key toward A");
    let mut a = Phone::new(
        Arc::new(phone_a),
        answered.remote_rtp,
        Some(SecureLeg::new(&key_a.key, &engine_key_a.key)),
        0x0A0A_0A0A,
    );
    a.sdes_suite = true;
    let mut b = Phone::new(
        Arc::new(phone_b),
        offered.remote_rtp,
        Some(SecureLeg::new(&key_b.key, &engine_key_b.key)),
        0x0B0B_0B0B,
    );
    b.sdes_suite = true;
    Rig {
        engine,
        call_id: "hold-transcrypt",
        a,
        b,
        original: PipelineKind::SrtpTranscrypt,
        held: PipelineKind::SrtpTranscryptMedia,
        reoffer: None,
    }
}

/// A plain A and a DTLS-SRTP B (`PipelineKind::Dtls`).
async fn dtls_rig() -> Rig {
    let engine = engine_with_dispatcher();
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let peer_b = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind b"),
    );
    let addr_b = peer_b.local_addr().expect("addr b");
    let offered = offer_from_a(
        &engine,
        "hold-dtls",
        sdp_for(addr_a, true),
        ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            ..Default::default()
        },
    )
    .await;
    let engine_fingerprint = offered.fingerprint.clone().expect("engine fingerprint");
    let peer_cert = DtlsCertificate::generate().expect("peer cert");
    let answered = answer_from_b(
        &engine,
        "hold-dtls",
        dtls_answer_sdp(addr_b, 0, "PCMU", &peer_cert, sdp::Setup::Active),
        Default::default(),
    )
    .await;
    let leg = peer_dtls_handshake(
        peer_b.clone(),
        addr_b,
        offered.remote_rtp,
        &peer_cert,
        &engine_fingerprint,
    )
    .await;
    Rig {
        engine,
        call_id: "hold-dtls",
        a: Phone::new(Arc::new(phone_a), answered.remote_rtp, None, 0x0A0A_0A0A),
        b: Phone::new(peer_b, offered.remote_rtp, Some(leg), 0x0B0B_0B0B),
        original: PipelineKind::Dtls,
        held: PipelineKind::DtlsMedia,
        reoffer: Some(Reoffer {
            sdp: sdp_for(addr_a, true),
            profile: ProfileFlags {
                transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                ..Default::default()
            },
            answer: dtls_answer_sdp(addr_b, 0, "PCMU", &peer_cert, sdp::Setup::Active),
            far_addr: addr_b,
        }),
    }
}

/// A plain A and a DTLS-SRTP B behind ICE (`PipelineKind::Dtls` on an ICE-gated leg): B's handshake
/// starts only on the source its connectivity check validated (RFC 8445 §12.1.1).
async fn dtls_ice_rig() -> Rig {
    let engine = engine_with_dispatcher();
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let peer_b = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind b"),
    );
    let addr_b = peer_b.local_addr().expect("addr b");
    let offered = offer_from_a(
        &engine,
        "hold-dtls-ice",
        sdp_for(addr_a, true),
        ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            ice: Some("force".into()),
            ..Default::default()
        },
    )
    .await;
    let engine_fingerprint = offered.fingerprint.clone().expect("engine fingerprint");
    let engine_ufrag = offered.ice_ufrag.clone().expect("engine ufrag");
    let engine_pwd = offered.ice_pwd.clone().expect("engine pwd");
    let peer_cert = DtlsCertificate::generate().expect("peer cert");
    let answer_sdp = format!(
        "{}a=ice-ufrag:BBBBBB\r\na=ice-pwd:bpasswordbpasswordbpas\r\n\
         a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
        dtls_answer_sdp(addr_b, 0, "PCMU", &peer_cert, sdp::Setup::Active),
        addr_b.ip(),
        addr_b.port(),
    );
    let answered = answer_from_b(
        &engine,
        "hold-dtls-ice",
        answer_sdp.clone(),
        Default::default(),
    )
    .await;
    // B checks the engine from its real transport, which validates the ICE leg.
    let check = nominating_binding_request(
        &[9u8; 12],
        &format!("{engine_ufrag}:BBBBBB"),
        engine_pwd.as_bytes(),
    );
    peer_b
        .send_to(&check, offered.remote_rtp)
        .await
        .expect("check");
    // A is a plain phone, but `ice: force` gates both of the engine's legs on a check.
    let near_check = nominating_binding_request(
        &[8u8; 12],
        &format!(
            "{}:{A_UFRAG}",
            answered.ice_ufrag.clone().expect("engine ufrag toward A")
        ),
        answered
            .ice_pwd
            .clone()
            .expect("engine pwd toward A")
            .as_bytes(),
    );
    phone_a
        .send_to(&near_check, answered.remote_rtp)
        .await
        .expect("A's check");
    let leg = drive_peer_dtls(
        peer_b.clone(),
        offered.remote_rtp,
        &peer_cert,
        &engine_fingerprint,
        siphon_rtp_dtls::DtlsRole::Client,
        true,
    )
    .await;
    Rig {
        engine,
        call_id: "hold-dtls-ice",
        a: Phone::new(Arc::new(phone_a), answered.remote_rtp, None, 0x0A0A_0A0A),
        b: Phone::new(peer_b, offered.remote_rtp, Some(leg), 0x0B0B_0B0B),
        original: PipelineKind::Dtls,
        held: PipelineKind::DtlsMedia,
        reoffer: None,
    }
}

/// A DTLS-SRTP A behind ICE and a plain B (`PipelineKind::DtlsOfferer`).
async fn dtls_offerer_rig() -> Rig {
    let engine = engine_with_dispatcher();
    let socket_a = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("bind a"),
    );
    let addr_a = socket_a.local_addr().expect("addr a");
    let signalled: SocketAddr = "192.0.2.10:40000".parse().expect("signalled address");
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let caller = DtlsCertificate::generate().expect("caller cert");
    let call_id = "hold-dtls-offerer";
    let offered = offer_from_a(
        &engine,
        call_id,
        nated_ice_dtls_offerer_sdp(signalled, addr_a, &caller.fingerprint()),
        plain_far_leg(),
    )
    .await;
    let answered = answer_from_b(&engine, call_id, sdp_for(addr_b, true), Default::default()).await;
    let engine_near = answered.remote_rtp;
    let engine_fingerprint = answered.fingerprint.clone().expect("engine fingerprint");
    let ufrag = answered.ice_ufrag.clone().expect("engine ufrag");
    let pwd = answered.ice_pwd.clone().expect("engine pwd");
    // A checks the engine from its real transport, which validates the ICE leg.
    let check =
        nominating_binding_request(&[7u8; 12], &format!("{ufrag}:{A_UFRAG}"), pwd.as_bytes());
    socket_a.send_to(&check, engine_near).await.expect("check");
    let leg = peer_dtls_handshake_server(
        socket_a.clone(),
        addr_a,
        engine_near,
        &caller,
        &engine_fingerprint,
    )
    .await;
    Rig {
        engine,
        call_id: "hold-dtls-offerer",
        a: Phone::new(socket_a, engine_near, Some(leg), 0x0A0A_0A0A),
        b: Phone::new(Arc::new(phone_b), offered.remote_rtp, None, 0x0B0B_0B0B),
        original: PipelineKind::DtlsOfferer,
        held: PipelineKind::DtlsOffererMedia,
        reoffer: None,
    }
}

// ---- the cycle on every kind ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plain_relay_is_held_in_the_decoding_actor_and_released() {
    assert_hold_cycle(plain_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_srtp_bridge_is_held_and_released_on_one_stream_under_its_own_keys() {
    assert_hold_cycle(srtp_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_srtp_offerer_bridge_is_held_and_released_on_one_stream_under_its_own_keys() {
    assert_hold_cycle(srtp_offerer_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_srtp_transcrypt_bridge_is_held_and_released_on_one_stream_under_its_own_keys() {
    assert_hold_cycle(srtp_transcrypt_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_bridge_is_held_and_released_on_one_stream_under_its_own_association() {
    assert_hold_cycle(dtls_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ice_dtls_bridge_is_held_and_released_on_one_stream_under_its_own_association() {
    assert_hold_cycle(dtls_ice_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ice_dtls_offerer_bridge_is_held_and_released_on_one_stream_under_its_own_association() {
    assert_hold_cycle(dtls_offerer_rig().await).await;
}

// ---- the re-offer, the refusals and the taps -----------------------------------------------------

impl Rig {
    async fn reoffer(&self) {
        let reoffer = self.reoffer.as_ref().expect("a rig with a re-offer");
        let result = reoffer_from(
            &self.engine,
            self.call_id,
            "a",
            reoffer.sdp.clone(),
            reoffer.profile.clone(),
        )
        .await;
        assert!(
            matches!(result, CmdResult::Ok { .. }),
            "re-offer: {result:?}"
        );
        answer_from_b(
            &self.engine,
            self.call_id,
            reoffer.answer.clone(),
            ProfileFlags::default(),
        )
        .await;
    }
}

/// The call is re-offered while held and answered: it stays held, on the actor's kind, with the same
/// live SRTP contexts (a packet B already sent is still a replay), and each party keeps receiving one
/// stream, the SSRC and sequence the bridge had been sending, through the re-offer and the release.
async fn assert_reoffer_while_held(mut rig: Rig) {
    rig.warm_up().await;
    let (mut at_a, mut at_b) = rig.run(6, LOUD, None).await;
    rig.hold().await.expect("held");
    let (held_a, held_b) = rig.run(4, LOUD, None).await;
    at_a.absorb(held_a);
    at_b.absorb(held_b);
    let replayed = rig.b.last_sent.clone();
    let legs_before = rig.engine.media.secure_legs(rig.call_id);

    rig.reoffer().await;
    // The replacement actor holds the very contexts the old one did: two contexts under one key would
    // number the same SRTCP index twice (RFC 3711 §9.1).
    let legs_after = rig.engine.media.secure_legs(rig.call_id);
    if let (Some(before), Some(after)) = (&legs_before.1, &legs_after.1) {
        assert!(
            Arc::ptr_eq(before, after),
            "the re-offer keeps the live SecureLeg, it does not rebuild it"
        );
    }
    assert_eq!(
        rig.kind(),
        rig.held,
        "a re-offer keeps the call on the actor's kind"
    );
    assert!(
        rig.engine.is_secure_held(rig.call_id),
        "and the call keeps its hold"
    );
    assert!(rig
        .engine
        .calls
        .get(rig.call_id)
        .expect("call")
        .promotion_reasons
        .contains(&PromotionReason::WsSplit));

    // The leg's replay window survived the rebuild: a datagram B had already sent is refused, not
    // decoded a second time (RFC 3711 §3.3.2).
    rig.b
        .socket
        .send_to(&replayed, rig.b.engine)
        .await
        .expect("replay");
    let replay = rig.a.listen(Duration::from_millis(120)).await;
    assert!(
        replay.media.is_empty(),
        "a replayed datagram is refused after the re-offer: {replay:?}"
    );

    // Audio crosses the rebuilt actor decoded, on the stream it had been sending.
    let (after_a, after_b) = rig.run(8, LOUD, None).await;
    at_a.absorb(after_a);
    at_b.absorb(after_b);
    rig.engine
        .media
        .control(rig.call_id, MediaControl::Silence(true));
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (silenced_a, silenced_b) = rig.run(5, LOUD, None).await;
    assert!(
        only_silence(&silenced_a) && only_silence(&silenced_b),
        "still the decoded path"
    );
    at_a.absorb(silenced_a);
    at_b.absorb(silenced_b);
    rig.engine
        .media
        .control(rig.call_id, MediaControl::Silence(false));
    tokio::time::sleep(Duration::from_millis(20)).await;

    rig.release().await;
    assert_eq!(rig.kind(), rig.original, "released onto its bridge");
    assert!(!rig.engine.is_secure_held(rig.call_id));
    let (bridge_a, bridge_b) = rig.run(8, LOUD, None).await;
    at_a.absorb(bridge_a);
    at_b.absorb(bridge_b);
    assert_one_stream(
        &at_b,
        rig.a.ssrc,
        "B hears A across the re-offer and the release",
    );
    assert_one_stream(
        &at_a,
        rig.b.ssrc,
        "A hears B across the re-offer and the release",
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reoffer_while_an_sdes_call_is_held_keeps_the_hold_and_the_keys() {
    assert_reoffer_while_held(srtp_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reoffer_while_a_dtls_call_is_held_keeps_the_hold_and_the_association() {
    assert_reoffer_while_held(dtls_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_rehandshake_while_held_releases_the_hold_before_the_new_association() {
    let mut rig = dtls_rig().await;
    rig.warm_up().await;
    rig.run(4, LOUD, None).await;
    rig.hold().await.expect("held");
    rig.run(4, LOUD, None).await;

    // B answers the re-offer with another certificate: a new association (RFC 8842 §3.1).
    let other = DtlsCertificate::generate().expect("second certificate");
    let (reoffer_sdp, reoffer_profile, far_addr) = {
        let reoffer = rig.reoffer.as_ref().expect("re-offer");
        (
            reoffer.sdp.clone(),
            reoffer.profile.clone(),
            reoffer.far_addr,
        )
    };
    let result = reoffer_from(&rig.engine, rig.call_id, "a", reoffer_sdp, reoffer_profile).await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    answer_from_b(
        &rig.engine,
        rig.call_id,
        dtls_answer_sdp(far_addr, 0, "PCMU", &other, sdp::Setup::Active),
        ProfileFlags::default(),
    )
    .await;
    assert!(
        !rig.engine.is_secure_held(rig.call_id),
        "the hold ended before the new association"
    );
    assert_eq!(
        rig.kind(),
        PipelineKind::Dtls,
        "the call is back on its DTLS bridge"
    );
    assert!(
        !rig.engine.media.is_media_call(rig.call_id),
        "no actor is left waiting for a key it will never get"
    );

    // The old association's media is dropped, never half-decoded...
    rig.b.send_frame(LOUD, 0).await;
    let stale = rig.a.listen(Duration::from_millis(150)).await;
    assert!(
        stale.media.is_empty(),
        "the old leg's media is dropped: {stale:?}"
    );
    // ...and the new one keys the bridge and carries media.
    let engine_fingerprint = rig.engine.engine_fingerprint().expect("engine fingerprint");
    let fresh = drive_peer_dtls(
        rig.b.socket.clone(),
        rig.b.engine,
        &other,
        &engine_fingerprint,
        siphon_rtp_dtls::DtlsRole::Client,
        false,
    )
    .await;
    rig.b.leg = Some(fresh);
    let mut heard = Heard::default();
    for _ in 0..40 {
        rig.b.send_frame(LOUD, 0).await;
        tokio::time::sleep(Duration::from_millis(15)).await;
        heard.absorb(rig.a.listen(Duration::from_millis(10)).await);
        if !heard.media.is_empty() {
            break;
        }
    }
    assert!(!heard.media.is_empty(), "the new association relays media");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_that_cannot_be_split_is_refused_with_its_token() {
    let rig = plain_rig().await;
    // Not answered yet.
    let (_phone, addr) = phone().await;
    offer_from_a(
        &rig.engine,
        "unanswered",
        sdp_for(addr, true),
        Default::default(),
    )
    .await;
    let refused = rig
        .engine
        .hold_in_userspace(
            "unanswered",
            PromotionReason::WsSplit,
            PromoteMode::Processing,
        )
        .await;
    assert!(refused
        .expect_err("refused")
        .starts_with("ws-split-not-answered"));

    // Answered by the engine itself.
    rig.engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "local".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr, true),
                profile: Default::default(),
            },
        )
        .await;
    let refused = rig
        .engine
        .hold_in_userspace("local", PromotionReason::WsSplit, PromoteMode::Processing)
        .await;
    assert!(refused
        .expect_err("refused")
        .starts_with("ws-split-answer-local"));

    // A leg seated in a room.
    let seated = rig
        .engine
        .handle(
            CLIENT,
            Command::ConferenceSeat {
                call_id: rig.call_id.into(),
                from_tag: "b".into(),
                conference_id: "room".into(),
                role: siphon_rtp_proto::ConferenceRole::Talker,
                dtmf: siphon_rtp_proto::ConferenceDtmf::Events,
            },
        )
        .await;
    assert!(matches!(seated, CmdResult::Ok { .. }), "{seated:?}");
    let refused = rig.hold().await;
    assert!(refused.expect_err("refused").starts_with("ws-split-seated"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_with_a_takeover_or_a_split_already_on_it_is_refused() {
    let rig = srtp_rig().await;
    rig.hold().await.expect("held once");
    let refused = rig.hold().await;
    assert!(
        refused
            .expect_err("refused")
            .starts_with("ws-split-already-bridged"),
        "a second split on a held call"
    );
    rig.release().await;
    // A call a WebSocket takeover owns has no far party to split.
    rig.engine
        .calls
        .get_mut(rig.call_id)
        .expect("call")
        .pipeline = PipelineKind::Ws;
    let refused = rig.hold().await;
    assert!(refused
        .expect_err("refused")
        .starts_with("ws-split-already-bridged"));
}

/// A tee or a recording rides the bridge's plaintext taps; they keep receiving while the actor holds
/// the call and when the bridge has it back, from the same sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_taps_a_bridge_carried_ride_along_a_hold_and_a_release() {
    let mut rig = srtp_rig().await;
    rig.warm_up().await;
    let (near_rtp, _) = {
        let call = rig.engine.calls.get(rig.call_id).expect("call");
        (call.near.rtp.id, 0)
    };
    let (sender, tapped) = flume::bounded(256);
    assert!(rig.engine.bridge.add_plain_tap(near_rtp, "tee", sender));
    let count = |tapped: &flume::Receiver<bytes::Bytes>| tapped.try_iter().count();

    rig.run(6, LOUD, None).await;
    assert!(count(&tapped) >= 5, "tapped on the bridge");
    rig.hold().await.expect("held");
    rig.run(6, LOUD, None).await;
    assert!(
        count(&tapped) >= 5,
        "the actor feeds the same tap while it holds the call"
    );
    rig.release().await;
    rig.run(6, LOUD, None).await;
    assert!(
        count(&tapped) >= 5,
        "and the bridge feeds it again once it has the call back"
    );
}

/// Deleting a call while it is held tears down what the hold moved: the actor, the bridge flows and
/// the DTLS association's tasks all drain, with nothing left owning an endpoint.
async fn assert_delete_while_held_drains(mut rig: Rig) {
    rig.warm_up().await;
    rig.hold().await.expect("held");
    rig.run(3, LOUD, None).await;
    let deleted = rig
        .engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }), "{deleted:?}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(rig.engine.calls.get(rig.call_id).is_none());
    assert!(
        !rig.engine.media.is_media_call(rig.call_id),
        "the actor is gone"
    );
    assert_eq!(
        rig.engine.dtls_bridge().session_count(),
        0,
        "no association is left running"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_held_sdes_call_drains_the_actor() {
    assert_delete_while_held_drains(srtp_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_held_dtls_call_drains_the_actor_and_the_association() {
    assert_delete_while_held_drains(dtls_rig().await).await;
}

/// An RTP socket and the RTCP socket one port above it (RFC 3550 §11.1: the default pairing).
async fn phone_with_rtcp(ip: Ipv4Addr) -> (UdpSocket, UdpSocket, SocketAddr) {
    for _ in 0..200 {
        let rtp = UdpSocket::bind((ip, 0)).await.expect("bind rtp");
        let addr = rtp.local_addr().expect("addr");
        if let Ok(rtcp) = UdpSocket::bind((ip, addr.port().wrapping_add(1))).await {
            return (rtp, rtcp, addr);
        }
    }
    panic!("no free RTP/RTCP port pair");
}

/// A secure caller and a plain callee that both keep RTCP on a port of its own (no `a=rtcp-mux`):
/// the companion RTCP flows move into the actor's relays with the call and back, and the caller's
/// SRTCP index keeps counting through both hand-overs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_non_muxed_sdes_call_keeps_its_rtcp_flowing_through_a_hold() {
    let engine = engine_with_dispatcher();
    let (rtp_a, rtcp_a, addr_a) = phone_with_rtcp(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (rtp_b, rtcp_b, addr_b) = phone_with_rtcp(Ipv4Addr::new(127, 0, 0, 3)).await;
    let key_a = sdes_key();
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "hold-nomux".into(),
                from_tag: "a".into(),
                sdp: format!(
                    "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
                     m=audio {port} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na={crypto}\r\n",
                    ip = addr_a.ip(),
                    port = addr_a.port(),
                    crypto = key_a.to_attribute_value(),
                ),
                profile: Default::default(),
            },
        )
        .await;
    let offered = sdp::parse(&ok_sdp_text(&offered)).expect("offer");
    let answered = answer_from_b(
        &engine,
        "hold-nomux",
        sdp_single_codec_nomux(addr_b, 0, "PCMU"),
        Default::default(),
    )
    .await;
    let engine_key = *answered.crypto.first().expect("engine key toward A");
    let (engine_near, engine_near_rtcp) = (answered.remote_rtp, answered.remote_rtcp);
    let (engine_far, engine_far_rtcp) = (offered.remote_rtp, offered.remote_rtcp);
    assert_ne!(
        engine_near_rtcp, engine_near,
        "the call keeps RTCP on its own port"
    );
    let mut a = SecureLeg::new(&key_a.key, &engine_key.key);

    let mut indexes = Vec::new();
    let mut plain_reports = 0usize;
    for phase in 0..3 {
        if phase == 1 {
            engine
                .hold_in_userspace(
                    "hold-nomux",
                    PromotionReason::WsSplit,
                    PromoteMode::Processing,
                )
                .await
                .expect("held");
            assert_eq!(
                engine.calls.get("hold-nomux").expect("call").pipeline,
                PipelineKind::SrtpOffererMedia
            );
        }
        if phase == 2 {
            engine
                .release_userspace_hold("hold-nomux", PromotionReason::WsSplit)
                .await;
            assert_eq!(
                engine.calls.get("hold-nomux").expect("call").pipeline,
                PipelineKind::SrtpOfferer
            );
        }
        // Audio first, so the call is plainly alive in this phase.
        let mut sealed = Vec::new();
        a.protect(&g711_rtp(0, 100 + phase, 0x0A0A_0A0A, LOUD), &mut sealed)
            .expect("protect");
        rtp_a.send_to(&sealed, engine_near).await.expect("send");
        let _ = recv(&rtp_b).await;
        rtp_b
            .send_to(&g711_rtp(0, 200 + phase, 0x0B0B_0B0B, LOUD), engine_far)
            .await
            .expect("send");
        let _ = recv(&rtp_a).await;
        // B's report reaches A as SRTCP on A's own RTCP port, under A's counting index.
        let mut report = vec![0x80, 200, 0x00, 0x06];
        report.extend_from_slice(&0x0B0B_0B0Bu32.to_be_bytes());
        report.extend_from_slice(&[0u8; 20]);
        rtcp_b
            .send_to(&report, engine_far_rtcp)
            .await
            .expect("send report");
        let (sealed_report, _) = recv(&rtcp_a).await;
        let mut clear = Vec::new();
        a.unprotect(&sealed_report, &mut clear)
            .expect("A decrypts the callee's report under the engine's key");
        indexes.push(srtcp_index(&sealed_report));
        // A's report reaches B in the clear on B's RTCP port.
        let mut sealed = Vec::new();
        let mut report = vec![0x80, 200, 0x00, 0x06];
        report.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
        report.extend_from_slice(&[0u8; 20]);
        a.protect(&report, &mut sealed).expect("protect report");
        rtcp_a
            .send_to(&sealed, engine_near_rtcp)
            .await
            .expect("send report");
        let (plain_report, _) = recv(&rtcp_b).await;
        assert_eq!(&plain_report[..2], &[0x80, 200]);
        plain_reports += 1;
    }
    assert_eq!(plain_reports, 3, "A's report crossed in every phase");
    assert_eq!(
        indexes
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .collect::<Vec<_>>(),
        vec![1, 1],
        "the SRTCP index toward A counts on through both hand-overs: {indexes:?}"
    );
}

/// An actor that stops answering cannot be stopped cleanly: the bridge must already own the
/// endpoints, and carry on from the peers' own numbering, rather than leave the call without a media
/// path.
async fn assert_release_survives_an_unresponsive_actor(mut rig: Rig) {
    rig.warm_up().await;
    rig.hold().await.expect("held");
    rig.run(3, LOUD, None).await;
    let _unread = rig
        .engine
        .media
        .stall_mailbox(rig.call_id)
        .expect("a registered actor");
    rig.release().await;
    assert_eq!(rig.kind(), rig.original, "the call is back on its bridge");
    assert!(!rig.engine.is_secure_held(rig.call_id));
    let mut heard = (Heard::default(), Heard::default());
    for _ in 0..40 {
        let (at_a, at_b) = rig.exchange(LOUD, 0).await;
        heard.0.absorb(at_a);
        heard.1.absorb(at_b);
        if heard.0.media.len() >= 5 && heard.1.media.len() >= 5 {
            break;
        }
    }
    assert!(
        heard.0.media.len() >= 5 && heard.1.media.len() >= 5,
        "media flows through the bridge it came back to: {heard:?}"
    );
    assert_eq!(heard.0.rejected + heard.1.rejected, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_release_keeps_a_media_path_when_the_actor_stops_answering() {
    assert_release_survives_an_unresponsive_actor(srtp_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_release_keeps_a_media_path_when_the_actor_stops_answering() {
    assert_release_survives_an_unresponsive_actor(dtls_rig().await).await;
}

/// A plain A that keeps RTCP on a port of its own, and a DTLS B that multiplexes it: A's reports reach
/// B as SRTCP and B's reach A on A's RTCP port, before the hold, while it is held and after.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_calls_plain_rtcp_port_keeps_flowing_through_a_hold() {
    let engine = engine_with_dispatcher();
    let (rtp_a, rtcp_a, addr_a) = phone_with_rtcp(Ipv4Addr::new(127, 0, 0, 2)).await;
    let peer_b = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind b"),
    );
    let addr_b = peer_b.local_addr().expect("addr b");
    let offered = offer_from_a(
        &engine,
        "hold-dtls-rtcp",
        sdp_for(addr_a, false),
        ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            ..Default::default()
        },
    )
    .await;
    let engine_fingerprint = offered.fingerprint.clone().expect("engine fingerprint");
    let peer_cert = DtlsCertificate::generate().expect("peer cert");
    let answered = answer_from_b(
        &engine,
        "hold-dtls-rtcp",
        dtls_answer_sdp(addr_b, 0, "PCMU", &peer_cert, sdp::Setup::Active),
        Default::default(),
    )
    .await;
    let engine_far = offered.remote_rtp;
    let (engine_near, engine_near_rtcp) = (answered.remote_rtp, answered.remote_rtcp);
    assert_ne!(
        engine_near_rtcp, engine_near,
        "A keeps RTCP on its own port"
    );
    let mut leg_b = peer_dtls_handshake(
        peer_b.clone(),
        addr_b,
        engine_far,
        &peer_cert,
        &engine_fingerprint,
    )
    .await;
    // Wait for media both ways.
    let mut buffer = [0u8; 2048];
    for sequence in 0..60u16 {
        let mut sealed = Vec::new();
        leg_b
            .protect(&g711_rtp(0, 500 + sequence, 0x0B0B_0B0B, LOUD), &mut sealed)
            .expect("protect");
        peer_b.send_to(&sealed, engine_far).await.expect("send");
        if timeout(Duration::from_millis(40), rtp_a.recv_from(&mut buffer))
            .await
            .is_ok()
        {
            break;
        }
    }
    let mut reports_at_a = 0usize;
    let mut reports_at_b = 0usize;
    for phase in 0..3u16 {
        if phase == 1 {
            engine
                .hold_in_userspace(
                    "hold-dtls-rtcp",
                    PromotionReason::WsSplit,
                    PromoteMode::Processing,
                )
                .await
                .expect("held");
        }
        if phase == 2 {
            engine
                .release_userspace_hold("hold-dtls-rtcp", PromotionReason::WsSplit)
                .await;
        }
        // B's report, protected as SRTCP on the multiplexed port, arrives at A's RTCP port in the clear.
        let mut report = vec![0x80, 200, 0x00, 0x06];
        report.extend_from_slice(&0x0B0B_0B0Bu32.to_be_bytes());
        report.extend_from_slice(&[0u8; 20]);
        let mut sealed = Vec::new();
        leg_b.protect(&report, &mut sealed).expect("protect report");
        peer_b.send_to(&sealed, engine_far).await.expect("send");
        let (len, _) = timeout(Duration::from_millis(500), rtcp_a.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("phase {phase}: B's report reaches A's RTCP port"))
            .expect("recv");
        assert_eq!(&buffer[..2], &[0x80, 200], "{len} bytes of plain RTCP");
        reports_at_a += 1;
        // A's report from its RTCP port reaches B as SRTCP under the association's key.
        let mut report = vec![0x80, 200, 0x00, 0x06];
        report.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
        report.extend_from_slice(&[0u8; 20]);
        rtcp_a
            .send_to(&report, engine_near_rtcp)
            .await
            .expect("send");
        let (len, _) = timeout(Duration::from_millis(500), peer_b.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("phase {phase}: A's report reaches B"))
            .expect("recv");
        let mut clear = Vec::new();
        leg_b
            .unprotect(&buffer[..len], &mut clear)
            .expect("B decrypts A's report under the association's key");
        reports_at_b += 1;
    }
    assert_eq!((reports_at_a, reports_at_b), (3, 3));
}

/// Lawful interception (ETSI TS 103 221-2 X3) rides the call through a hold and a release: both
/// directions are delivered on the bridge, while the actor holds the call, and on the bridge again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interception_delivers_both_directions_through_a_hold_and_a_release() {
    use crate::x3::{ingress_directions, x3_channel, X3Taps};
    let mut rig = srtp_rig().await;
    rig.warm_up().await;
    let (near_rtp, far_rtp) = {
        let call = rig.engine.calls.get(rig.call_id).expect("call");
        (call.near.rtp.id, call.far_leg().rtp.id)
    };
    let (factory, delivery) = x3_channel(512);
    let (toward_a, toward_b) = ingress_directions(true);
    let destination: SocketAddr = "198.51.100.9:9000".parse().expect("addr");
    assert!(rig
        .engine
        .bridge
        .set_x3_tap(near_rtp, X3Taps::single(factory.tap(destination, toward_a))));
    assert!(rig
        .engine
        .bridge
        .set_x3_tap(far_rtp, X3Taps::single(factory.tap(destination, toward_b))));
    let delivered = |delivery: &crate::x3::X3Delivery| {
        let mut from_target = 0usize;
        let mut to_target = 0usize;
        for packet in delivery.packets.try_iter() {
            if packet.direction == toward_a {
                from_target += 1;
            } else {
                to_target += 1;
            }
        }
        (from_target, to_target)
    };
    for phase in ["on the bridge", "held", "released"] {
        if phase == "held" {
            rig.hold().await.expect("held");
        }
        if phase == "released" {
            rig.release().await;
        }
        let _ = delivered(&delivery);
        rig.run(8, LOUD, None).await;
        let (from_target, to_target) = delivered(&delivery);
        assert!(
            from_target >= 6 && to_target >= 6,
            "{phase}: both directions are delivered, got {from_target} from the target and {to_target} to it"
        );
    }
}

/// An SDES leg behind ICE (`ice: force` gates both of the engine's legs on a check).
async fn srtp_ice_rig() -> Rig {
    let engine = engine_with_dispatcher();
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "hold-srtp-ice".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    ice: Some("force".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offered = sdp::parse(&ok_sdp_text(&offered)).expect("offer");
    let engine_key = *offered.crypto.first().expect("engine key toward B");
    let key_b = sdes_key();
    let answer_sdp = format!(
        "{}a=ice-ufrag:BBBBBB\r\na=ice-pwd:bpasswordbpasswordbpas\r\n\
         a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
        savp_answer_sdp(addr_b, &key_b),
        addr_b.ip(),
        addr_b.port(),
    );
    let answered = answer_from_b(&engine, "hold-srtp-ice", answer_sdp, Default::default()).await;
    let check_b = nominating_binding_request(
        &[9u8; 12],
        &format!("{}:BBBBBB", offered.ice_ufrag.clone().expect("ufrag")),
        offered.ice_pwd.clone().expect("pwd").as_bytes(),
    );
    phone_b
        .send_to(&check_b, offered.remote_rtp)
        .await
        .expect("check");
    let check_a = nominating_binding_request(
        &[8u8; 12],
        &format!("{}:{A_UFRAG}", answered.ice_ufrag.clone().expect("ufrag")),
        answered.ice_pwd.clone().expect("pwd").as_bytes(),
    );
    phone_a
        .send_to(&check_a, answered.remote_rtp)
        .await
        .expect("check");
    let mut b = Phone::new(
        Arc::new(phone_b),
        offered.remote_rtp,
        Some(SecureLeg::new(&key_b.key, &engine_key.key)),
        0x0B0B_0B0B,
    );
    b.sdes_suite = true;
    Rig {
        engine,
        call_id: "hold-srtp-ice",
        a: Phone::new(Arc::new(phone_a), answered.remote_rtp, None, 0x0A0A_0A0A),
        b,
        original: PipelineKind::Srtp,
        held: PipelineKind::SrtpMedia,
        reoffer: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ice_sdes_bridge_is_held_and_released_on_one_stream_under_its_own_keys() {
    assert_hold_cycle(srtp_ice_rig().await).await;
}

/// The held actor sends on a clock of its own (a prompt, a bot's downlink), not one packet per packet
/// the peer sends, so under the continued SSRC it can be far ahead of the peer's numbering. If it
/// then cannot report its position at release, resuming the peer's numbering under that SSRC would
/// reuse SRTP indices (RFC 3711 §3.3.1, §9.1); the bridge must change SSRC instead (RFC 3550 §8.2).
async fn assert_no_index_reuse_when_the_actor_ran_ahead_and_cannot_report(mut rig: Rig) {
    use siphon_rtp_media::fanout::MediaSink as _;
    use siphon_rtp_media::player::{PcmPlayer, PcmRepeat, WavSource};
    use siphon_rtp_media::wav::WavRecorder;
    use std::collections::HashSet;

    rig.warm_up().await;
    let (_, mut at_b) = rig.run(5, LOUD, None).await;
    rig.hold().await.expect("held");

    // One second of prompt toward B: 50 packets under B's stream while A sends nothing (DTX).
    let mut recorder = WavRecorder::new(8000, 1);
    recorder.write_pcm(&[2000i16; 8000]);
    let source = WavSource::parse(&recorder.into_wav()).expect("wav");
    rig.engine.media.control(
        rig.call_id,
        MediaControl::PlayAudio {
            toward_a: false,
            request: Box::new(crate::media_pipeline::PlayRequest::Pcm(Box::new(
                PcmPlayer::new(&source, PcmRepeat::Times(1), 0),
            ))),
            overlay: false,
            gain: siphon_rtp_media::playback::Gain::unity(),
            duration_cap_ms: None,
            play_id: 1,
            reply: None,
        },
    );
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        at_b.absorb(rig.b.listen(Duration::from_millis(5)).await);
        let _ = rig.a.listen(Duration::from_millis(1)).await;
    }
    let sent_by_the_actor = at_b.media.len();
    assert!(
        sent_by_the_actor > 40,
        "the actor ran ahead: {sent_by_the_actor}"
    );
    let (_, held_b) = rig.run(3, LOUD, None).await;
    at_b.absorb(held_b);

    let _unread = rig
        .engine
        .media
        .stall_mailbox(rig.call_id)
        .expect("a registered actor");
    rig.release().await;
    assert_eq!(rig.kind(), rig.original);
    let (_, after_b) = rig.run(12, LOUD, None).await;
    assert!(
        after_b.media.len() >= 8,
        "the bridge carries on: {after_b:?}"
    );
    assert_eq!(after_b.rejected, 0, "everything after the release decrypts");
    at_b.absorb(after_b);

    assert_eq!(at_b.rejected, 0, "no packet was refused as a replay");
    let mut seen = HashSet::new();
    for packet in &at_b.media {
        assert!(
            seen.insert((packet.ssrc, packet.sequence)),
            "SRTP index (SSRC {:#x}, sequence {}) was used twice",
            packet.ssrc,
            packet.sequence
        );
    }
    let last = at_b.media.last().expect("media after the release");
    assert_ne!(
        last.ssrc, rig.a.ssrc,
        "without the actor's position the bridge changes SSRC rather than guess a numbering"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_release_after_the_actor_ran_ahead_and_cannot_report_reuses_no_index() {
    assert_no_index_reuse_when_the_actor_ran_ahead_and_cannot_report(srtp_rig().await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_release_after_the_actor_ran_ahead_and_cannot_report_reuses_no_index() {
    assert_no_index_reuse_when_the_actor_ran_ahead_and_cannot_report(dtls_rig().await).await;
}

/// On a symmetric leg (open gate, no ICE) the learned source and SSRC are all that keep a stranger
/// from becoming the reply destination. They go with the call into the actor and back, so a stranger
/// who sends first right after either move meets an established latch and is refused (RTPBleed,
/// docs/security-and-nat.md §4 layer 3), while the real peer is still served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_who_sends_first_after_a_hold_or_a_release_meets_the_established_latch() {
    let mut rig = srtp_rig_with(&["symmetric"]).await;
    rig.warm_up().await;
    rig.run(6, LOUD, None).await;
    let stranger = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 9), 0))
        .await
        .expect("bind stranger");
    let spray = |sequence: u16| g711_rtp(0, sequence, 0xBAD0_BAD0, LOUD);

    for moment in ["hold", "release"] {
        if moment == "hold" {
            rig.hold().await.expect("held");
        } else {
            rig.release().await;
        }
        // The stranger sends before the real peer does, repeatedly: the window in which a fresh latch
        // would adopt it.
        for sequence in 0..4 {
            stranger
                .send_to(&spray(sequence), rig.a.engine)
                .await
                .expect("stranger sends");
        }
        let (at_a, at_b) = rig.run(8, LOUD, None).await;
        assert!(
            at_b.media.iter().all(|packet| packet.ssrc != 0xBAD0_BAD0),
            "after the {moment} the stranger's stream reaches nobody"
        );
        assert!(
            at_b.media.len() >= 6 && at_a.media.len() >= 6,
            "after the {moment} the real peer is still served: {at_b:?}"
        );
        // And the reply still goes to the real peer: A hears B, the stranger hears nothing.
        let mut buffer = [0u8; 2048];
        assert!(
            timeout(Duration::from_millis(60), stranger.recv_from(&mut buffer))
                .await
                .is_err(),
            "after the {moment} nothing is sent to the stranger"
        );
    }
}

/// A held DTLS call whose plain peer moves its RTCP to another port in a re-offer: the RTCP routing
/// comes from the new answer, so B's reports reach the new port and A's report from it reaches B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_reoffer_while_held_takes_the_plain_peers_new_rtcp_port() {
    let engine = engine_with_dispatcher();
    let (rtp_a, rtcp_a, addr_a) = phone_with_rtcp(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_, moved_rtcp, _) = phone_with_rtcp(Ipv4Addr::new(127, 0, 0, 2)).await;
    let moved_port = moved_rtcp.local_addr().expect("addr").port();
    let peer_b = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind b"),
    );
    let addr_b = peer_b.local_addr().expect("addr b");
    let profile = ProfileFlags {
        transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
        ..Default::default()
    };
    let offered = offer_from_a(
        &engine,
        "hold-dtls-move",
        sdp_for(addr_a, false),
        profile.clone(),
    )
    .await;
    let engine_fingerprint = offered.fingerprint.clone().expect("engine fingerprint");
    let peer_cert = DtlsCertificate::generate().expect("peer cert");
    let answer = dtls_answer_sdp(addr_b, 0, "PCMU", &peer_cert, sdp::Setup::Active);
    let answered = answer_from_b(
        &engine,
        "hold-dtls-move",
        answer.clone(),
        Default::default(),
    )
    .await;
    let engine_far = offered.remote_rtp;
    let mut leg_b = peer_dtls_handshake(
        peer_b.clone(),
        addr_b,
        engine_far,
        &peer_cert,
        &engine_fingerprint,
    )
    .await;
    let mut buffer = [0u8; 2048];
    for sequence in 0..60u16 {
        let mut sealed = Vec::new();
        leg_b
            .protect(&g711_rtp(0, 500 + sequence, 0x0B0B_0B0B, LOUD), &mut sealed)
            .expect("protect");
        peer_b.send_to(&sealed, engine_far).await.expect("send");
        if timeout(Duration::from_millis(40), rtp_a.recv_from(&mut buffer))
            .await
            .is_ok()
        {
            break;
        }
    }
    engine
        .hold_in_userspace(
            "hold-dtls-move",
            PromotionReason::WsSplit,
            PromoteMode::Processing,
        )
        .await
        .expect("held");

    // A re-offers with its RTCP on another port (RFC 3605 `a=rtcp`), B answers as before.
    let moved_sdp = format!("{}a=rtcp:{moved_port}\r\n", sdp_for(addr_a, false));
    let result = reoffer_from(&engine, "hold-dtls-move", "a", moved_sdp, profile).await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    let reanswered = answer_from_b(&engine, "hold-dtls-move", answer, Default::default()).await;
    let engine_near_rtcp = reanswered.remote_rtcp;
    assert_eq!(
        answered.remote_rtcp, engine_near_rtcp,
        "the engine's own RTCP port is kept"
    );
    assert!(engine.is_secure_held("hold-dtls-move"));

    // B's report now reaches A's NEW RTCP port, not the old one.
    let mut report = vec![0x80, 200, 0x00, 0x06];
    report.extend_from_slice(&0x0B0B_0B0Bu32.to_be_bytes());
    report.extend_from_slice(&[0u8; 20]);
    let mut sealed = Vec::new();
    leg_b.protect(&report, &mut sealed).expect("protect report");
    peer_b.send_to(&sealed, engine_far).await.expect("send");
    timeout(
        Duration::from_millis(500),
        moved_rtcp.recv_from(&mut buffer),
    )
    .await
    .expect("B's report reaches the port A moved its RTCP to")
    .expect("recv");
    assert!(
        timeout(Duration::from_millis(100), rtcp_a.recv_from(&mut buffer))
            .await
            .is_err(),
        "and not the port it left"
    );
    // A's report from the new port reaches B under the association's key.
    let mut report = vec![0x80, 200, 0x00, 0x06];
    report.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
    report.extend_from_slice(&[0u8; 20]);
    moved_rtcp
        .send_to(&report, engine_near_rtcp)
        .await
        .expect("send");
    let (len, _) = timeout(Duration::from_millis(500), peer_b.recv_from(&mut buffer))
        .await
        .expect("A's report reaches B")
        .expect("recv");
    let mut clear = Vec::new();
    leg_b
        .unprotect(&buffer[..len], &mut clear)
        .expect("B decrypts it");
}

/// A plain source whose numbering jumps (legal plain RTP: a re-INVITE to another media server behind a
/// B2BUA, an SSRC reused after a gap) must not become an outage on the secure leg behind it: the
/// bridge carries on from its own position, so an independent receiver decrypts every packet.
async fn assert_a_discontinuity_is_no_outage(mut rig: Rig, first: u16, then: u16) {
    rig.warm_up().await;
    rig.a.next_sequence = first;
    let (_, mut at_b) = rig.run(10, LOUD, None).await;
    // A quiet gap, as a media server switch has.
    tokio::time::sleep(Duration::from_millis(200)).await;
    rig.a.next_sequence = then;
    let (_, after) = rig.run(20, LOUD, None).await;
    assert!(
        after.media.len() >= 18,
        "B keeps hearing A after the jump from {first} to {then}: {after:?}"
    );
    at_b.absorb(after);
    assert_eq!(
        at_b.rejected, 0,
        "everything decrypts at the independent receiver"
    );
    // One stream of A's SSRC, its sequence number never going back or jumping: the bridge numbered it.
    let from_a: Vec<_> = at_b
        .media
        .iter()
        .filter(|packet| packet.ssrc == rig.a.ssrc)
        .collect();
    let tail = &from_a[from_a.len() - 15..];
    for pair in tail.windows(2) {
        assert_eq!(
            pair[1].sequence,
            pair[0].sequence.wrapping_add(1),
            "{pair:?}"
        );
    }
    let mut seen = std::collections::HashSet::new();
    for packet in &from_a {
        assert!(
            seen.insert(packet.sequence),
            "sequence {} sent twice",
            packet.sequence
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_bridge_survives_a_plain_source_restarting_its_sequence_after_30000() {
    assert_a_discontinuity_is_no_outage(srtp_rig().await, 29_990, 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_bridge_survives_an_ssrc_reused_after_a_gap_on_a_new_sequence_base() {
    assert_a_discontinuity_is_no_outage(srtp_rig().await, 500, 61_000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_sdes_bridge_survives_a_forward_jump_of_49000() {
    assert_a_discontinuity_is_no_outage(srtp_rig().await, 1_000, 50_000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_bridge_survives_a_plain_source_restarting_its_sequence_after_30000() {
    assert_a_discontinuity_is_no_outage(dtls_rig().await, 29_990, 0).await;
}

/// A held call whose plain peer is legitimately moved by a re-offer (another media server, another
/// SSRC) is served: the latch learned from the old address is not carried to the new one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_reoffer_that_moves_the_peer_does_not_keep_the_old_latch() {
    let mut rig = srtp_rig_with(&["symmetric"]).await;
    rig.warm_up().await;
    rig.run(6, LOUD, None).await;
    rig.hold().await.expect("held");
    rig.run(4, LOUD, None).await;

    let (moved_socket, moved_addr) = phone().await;
    let result = reoffer_from(
        &rig.engine,
        rig.call_id,
        "a",
        sdp_for(moved_addr, true),
        ProfileFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            flags: vec!["symmetric".into()],
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    let reoffer = rig.reoffer.as_ref().expect("re-offer");
    answer_from_b(
        &rig.engine,
        rig.call_id,
        reoffer.answer.clone(),
        ProfileFlags {
            flags: vec!["symmetric".into()],
            ..Default::default()
        },
    )
    .await;
    assert!(rig.engine.is_secure_held(rig.call_id));

    // The new peer, on its new address under a new SSRC, is heard: the held call numbers what B
    // receives itself, so what shows is audio arriving at all.
    rig.a = Phone::new(Arc::new(moved_socket), rig.a.engine, None, 0x0C0C_0C0C);
    let mut heard = Heard::default();
    for _ in 0..12 {
        let (_, at_b) = rig.exchange(LOUD, 0).await;
        heard.absorb(at_b);
    }
    assert!(
        heard.media.len() >= 8,
        "the moved peer is served: {} packets",
        heard.media.len()
    );
}
