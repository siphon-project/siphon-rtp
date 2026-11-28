//! A DTLS-SRTP caller (a browser, RFC 5764) toward an SDES-SRTP callee (a desk phone, RFC 4568): the
//! engine terminates the caller's association and keys the callee with its own SDES key, in the crypto
//! bridge (`PipelineKind::DtlsOffererTranscrypt`) and in the transcode twin
//! (`PipelineKind::DtlsOffererTranscryptMedia`).
//!
//! Both parties are independent peers: the browser runs a real DTLS handshake against the engine and
//! keys its own `SecureLeg` from it, and the desk phone builds its own SRTP/SRTCP contexts from the
//! key the engine offered it and the key it answered, so neither shares a code path with the engine's
//! bridge. A packet only crosses when the engine keyed each side the way its SDP said.

use super::*;
use crate::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_dtls::DtlsCertificate;
use siphon_rtp_srtp::srtcp::SrtcpContext;
use siphon_rtp_srtp::SrtpContext;

/// What the call is built from: the codecs each side speaks, whether the desk phone multiplexes RTCP
/// onto its RTP port, and the far-leg directives of the offer.
#[derive(Clone)]
struct Shape {
    call_id: &'static str,
    /// The browser's payload type, rtpmap line (without `a=rtpmap:<pt> `) and the engine's name for it.
    caller_codec: (u8, &'static str),
    callee_codec: (u8, &'static str),
    /// Directives asking the offer toward B to carry the callee's codec (`codec-transcode-X`).
    flags: Vec<String>,
    callee_muxes_rtcp: bool,
    record: bool,
}

impl Shape {
    fn same_codec(call_id: &'static str) -> Self {
        Self {
            call_id,
            caller_codec: (0, "PCMU/8000"),
            callee_codec: (0, "PCMU/8000"),
            flags: Vec::new(),
            callee_muxes_rtcp: true,
            record: false,
        }
    }

    fn transcoded(call_id: &'static str) -> Self {
        Self {
            callee_codec: (8, "PCMA/8000"),
            flags: vec!["codec-transcode-PCMA".into()],
            ..Self::same_codec(call_id)
        }
    }
}

/// A desk phone's own crypto: one SRTP and one SRTCP context per direction, from the two SDES keys it
/// knows (the one the engine offered it and the one it answered).
struct DeskPhone {
    sends: SrtpContext,
    receives: SrtpContext,
    sends_rtcp: SrtcpContext,
    receives_rtcp: SrtcpContext,
}

impl DeskPhone {
    fn new(own: &CryptoAttribute, engines: &CryptoAttribute) -> Self {
        Self {
            sends: SrtpContext::from_key_material(&own.key),
            receives: SrtpContext::from_key_material(&engines.key),
            sends_rtcp: SrtcpContext::from_key_material(&own.key),
            receives_rtcp: SrtcpContext::from_key_material(&engines.key),
        }
    }

    fn seal(&mut self, plain: &[u8]) -> Vec<u8> {
        let mut sealed = Vec::new();
        self.sends.protect(plain, &mut sealed).expect("desk seal");
        sealed
    }

    fn open(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        let mut plain = Vec::new();
        self.receives.unprotect(datagram, &mut plain).ok()?;
        Some(plain)
    }
}

struct Rig {
    engine: Engine<UdpLoopbackDatapath>,
    call_id: &'static str,
    browser: Arc<UdpSocket>,
    addr_a: SocketAddr,
    desk: UdpSocket,
    addr_b: SocketAddr,
    desk_rtcp: Option<(UdpSocket, SocketAddr)>,
    caller: DtlsCertificate,
    phone: DeskPhone,
    engine_near: SocketAddr,
    engine_far: SocketAddr,
    engine_far_rtcp: SocketAddr,
    engine_fingerprint: sdp::Fingerprint,
    caller_leg: Option<SecureLeg>,
    offered_to_b: sdp::MediaInfo,
    answered_to_a: sdp::MediaInfo,
    callee_key: CryptoAttribute,
}

fn caller_sdp(
    addr: SocketAddr,
    shape: &Shape,
    fingerprint: &siphon_rtp_dtls::Fingerprint,
) -> String {
    let hex = fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let (payload_type, rtpmap) = shape.caller_codec;
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF {payload_type}\r\na=rtpmap:{payload_type} {rtpmap}\r\n\
         a=rtcp-mux\r\na=setup:actpass\r\na=fingerprint:{hash} {hex}\r\n",
        ip = addr.ip(),
        port = addr.port(),
        hash = fingerprint.hash_function,
    )
}

fn callee_sdp(
    addr: SocketAddr,
    rtcp: Option<SocketAddr>,
    shape: &Shape,
    key: &CryptoAttribute,
) -> String {
    let (payload_type, rtpmap) = shape.callee_codec;
    let rtcp_line = match rtcp {
        None => "a=rtcp-mux\r\n".to_string(),
        Some(rtcp) => format!("a=rtcp:{}\r\n", rtcp.port()),
    };
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/SAVP {payload_type}\r\na=rtpmap:{payload_type} {rtpmap}\r\n\
         {rtcp_line}a={crypto}\r\n",
        ip = addr.ip(),
        port = addr.port(),
        crypto = key.to_attribute_value(),
    )
}

fn far_profile(shape: &Shape) -> ProfileFlags {
    ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        flags: shape.flags.clone(),
        ..Default::default()
    }
}

/// Offer and answer the call, without running the browser's handshake.
async fn rig(shape: Shape) -> Rig {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let browser = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), 0))
            .await
            .expect("bind a"),
    );
    let addr_a = browser.local_addr().expect("addr a");
    let (desk, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let desk_rtcp = if shape.callee_muxes_rtcp {
        None
    } else {
        Some(phone_at(Ipv4Addr::new(127, 0, 0, 3)).await)
    };
    let caller = DtlsCertificate::generate().expect("caller cert");
    let callee_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("callee key");

    let offered_to_b = offer_from_a(
        &engine,
        shape.call_id,
        caller_sdp(addr_a, &shape, &caller.fingerprint()),
        far_profile(&shape),
    )
    .await;
    let answered_to_a = answer_from_b(
        &engine,
        shape.call_id,
        callee_sdp(
            addr_b,
            desk_rtcp.as_ref().map(|(_, address)| *address),
            &shape,
            &callee_key,
        ),
        ProfileFlags {
            record_call: shape.record,
            ..Default::default()
        },
    )
    .await;
    let key_toward_b = *offered_to_b
        .crypto
        .first()
        .expect("the engine's key toward B");
    Rig {
        engine_near: answered_to_a.remote_rtp,
        engine_far: offered_to_b.remote_rtp,
        // The engine's own RTCP port toward B, which B reaches when it declines `a=rtcp-mux`: the
        // offer's multiplexed address is the RTP port.
        engine_far_rtcp: engine
            .calls
            .get(shape.call_id)
            .and_then(|call| call.far)
            .and_then(|far| far.rtcp)
            .map_or(offered_to_b.remote_rtcp, |endpoint| endpoint.local_addr),
        engine_fingerprint: answered_to_a
            .fingerprint
            .clone()
            .expect("the engine's fingerprint in A's answer"),
        phone: DeskPhone::new(&callee_key, &key_toward_b),
        engine,
        call_id: shape.call_id,
        browser,
        addr_a,
        desk,
        addr_b,
        desk_rtcp,
        caller,
        caller_leg: None,
        offered_to_b,
        answered_to_a,
        callee_key,
    }
}

impl Rig {
    /// The browser's DTLS handshake. The engine answered `actpass` with `active`, so the browser is
    /// the DTLS server.
    async fn handshake(&mut self) {
        self.caller_leg = Some(
            peer_dtls_handshake_server(
                self.browser.clone(),
                self.addr_a,
                self.engine_near,
                &self.caller,
                &self.engine_fingerprint,
            )
            .await,
        );
    }

    fn leg(&mut self) -> &mut SecureLeg {
        self.caller_leg.as_mut().expect("the browser handshook")
    }

    fn kind(&self) -> PipelineKind {
        self.engine.calls.get(self.call_id).expect("call").pipeline
    }

    /// What the desk phone receives on `socket` within the wait, if it is RTP/RTCP.
    async fn desk_receive(socket: &UdpSocket, wait: Duration) -> Option<Vec<u8>> {
        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(wait, socket.recv_from(&mut buffer))
            .await
            .ok()?
            .ok()?;
        Some(buffer[..len].to_vec())
    }

    /// What the browser receives that is media (not a DTLS record), within the wait.
    async fn browser_receive(&self, wait: Duration) -> Option<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + wait;
        let mut buffer = [0u8; 2048];
        loop {
            let remaining = deadline.checked_duration_since(tokio::time::Instant::now())?;
            let (len, _) = timeout(remaining, self.browser.recv_from(&mut buffer))
                .await
                .ok()?
                .ok()?;
            if (128..=191).contains(&buffer[0]) {
                return Some(buffer[..len].to_vec());
            }
        }
    }

    /// The browser sends `plain`; what the desk phone receives of it, opened with its own key. Sealed
    /// once and resent across the window between the handshake finishing and the engine keying its side.
    async fn browser_to_desk(&mut self, plain: &[u8]) -> Vec<u8> {
        let mut sealed = Vec::new();
        self.leg()
            .protect(plain, &mut sealed)
            .expect("browser seals");
        for _ in 0..40 {
            self.browser
                .send_to(&sealed, self.engine_near)
                .await
                .expect("a send");
            if let Some(datagram) = Self::desk_receive(&self.desk, Duration::from_millis(150)).await
            {
                assert_ne!(datagram, plain, "the desk phone is never handed plaintext");
                assert_ne!(datagram, sealed, "nor the browser's own ciphertext");
                return self
                    .phone
                    .open(&datagram)
                    .expect("the desk phone opens it under the key the engine offered");
            }
        }
        panic!("the desk phone never received the browser's media");
    }

    /// The desk phone sends `plain`; what the browser receives of it, opened with its own DTLS keys.
    async fn desk_to_browser(&mut self, plain: &[u8]) -> Vec<u8> {
        let sealed = self.phone.seal(plain);
        for _ in 0..40 {
            self.desk
                .send_to(&sealed, self.engine_far)
                .await
                .expect("b send");
            if let Some(datagram) = self.browser_receive(Duration::from_millis(150)).await {
                assert_ne!(datagram, plain, "the browser is never handed plaintext");
                let mut opened = Vec::new();
                self.leg()
                    .unprotect(&datagram, &mut opened)
                    .expect("the browser opens it under the handshake's keys");
                return opened;
            }
        }
        panic!("the browser never received the desk phone's media");
    }

    /// The browser sends the RTCP `report` as SRTCP; whether the desk phone receives it, opened under
    /// the key the engine offered it, on its RTCP port when it keeps one. The engine's own RTCP toward
    /// the phone may arrive first, so datagrams are read until the report's own comes.
    ///
    /// `rewritten`: the pipeline re-originates the stream, so it rewrites the report's sender SSRC to
    /// the one it sends under (RFC 3550 §6.4.1) and only the header and length are compared.
    async fn browser_rtcp_to_desk(&mut self, report: &[u8], rewritten: bool) -> bool {
        let mut sealed = Vec::new();
        self.leg()
            .protect(report, &mut sealed)
            .expect("browser seals SRTCP");
        for _ in 0..20 {
            self.browser
                .send_to(&sealed, self.engine_near)
                .await
                .expect("send");
            let socket = self
                .desk_rtcp
                .as_ref()
                .map_or(&self.desk, |(socket, _)| socket);
            while let Some(datagram) = Self::desk_receive(socket, Duration::from_millis(150)).await
            {
                let mut opened = Vec::new();
                if self
                    .phone
                    .receives_rtcp
                    .unprotect(&datagram, &mut opened)
                    .is_ok()
                    && opened.len() == report.len()
                    && opened[..4] == report[..4]
                    && (rewritten || opened == report)
                {
                    return true;
                }
            }
        }
        false
    }

    /// The desk phone sends the RTCP `report` as SRTCP (from its RTCP port when it keeps one); whether
    /// the browser receives it, opened under the handshake's keys.
    async fn desk_rtcp_to_browser(&mut self, report: &[u8]) -> bool {
        let mut sealed = Vec::new();
        self.phone
            .sends_rtcp
            .protect(report, &mut sealed)
            .expect("desk seals SRTCP");
        for _ in 0..20 {
            match &self.desk_rtcp {
                Some((socket, _)) => socket.send_to(&sealed, self.engine_far_rtcp).await,
                None => self.desk.send_to(&sealed, self.engine_far).await,
            }
            .expect("send");
            while let Some(datagram) = self.browser_receive(Duration::from_millis(150)).await {
                let mut opened = Vec::new();
                let ok = self.leg().unprotect(&datagram, &mut opened).is_ok();
                if ok && opened == report {
                    return true;
                }
            }
        }
        false
    }
}

fn receiver_report(ssrc: u32) -> Vec<u8> {
    let mut report = vec![0x80, 201, 0x00, 0x01];
    report.extend_from_slice(&ssrc.to_be_bytes());
    report
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dtls_caller_is_bridged_to_an_sdes_callee_under_each_partys_own_keying() {
    let mut rig = rig(Shape::same_codec("dtls-sdes-relay")).await;
    assert_eq!(rig.kind(), PipelineKind::DtlsOffererTranscrypt);

    // Neither party sees the other's keying. B is offered SDES with the engine's own key, and no
    // fingerprint; A is answered with the engine's fingerprint, and no crypto line.
    assert!(
        rig.offered_to_b.secure && !rig.offered_to_b.dtls && rig.offered_to_b.fingerprint.is_none(),
        "B is offered SDES-SRTP, not A's DTLS-SRTP"
    );
    assert_eq!(rig.offered_to_b.crypto.len(), 1);
    assert!(
        rig.answered_to_a.dtls
            && rig.answered_to_a.fingerprint.is_some()
            && rig.answered_to_a.crypto.is_empty(),
        "A is answered as a DTLS peer, with no SDES key of B's"
    );
    assert_ne!(
        rig.offered_to_b.crypto[0].key.master_key, rig.callee_key.key.master_key,
        "the engine's key toward B is its own, never B's echoed"
    );

    rig.handshake().await;

    // Audio both ways.
    let from_a = g711_rtp(0, 7, 0x0A0A_0A0A, 0x20);
    assert_eq!(rig.browser_to_desk(&from_a).await, from_a);
    let from_b = g711_rtp(0, 11, 0x0B0B_0B0B, 0x40);
    assert_eq!(rig.desk_to_browser(&from_b).await, from_b);

    // RTCP both ways, each side under its own keying (the browser muxes RTCP onto the RTP port).
    assert!(
        rig.browser_rtcp_to_desk(&receiver_report(0x0A0A_0A0A), false)
            .await,
        "A's SRTCP reaches B under the key the engine offered"
    );
    assert!(
        rig.desk_rtcp_to_browser(&receiver_report(0x0B0B_0B0B))
            .await,
        "B's SRTCP reaches A under the handshake's keys"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_desk_phones_rtcp_is_carried_to_a_dtls_caller_and_back_by_the_bridge_on_a_port_of_its_own(
) {
    let mut shape = Shape::same_codec("dtls-sdes-relay-rtcp");
    shape.callee_muxes_rtcp = false;
    let mut rig = rig(shape).await;
    assert_eq!(rig.kind(), PipelineKind::DtlsOffererTranscrypt);
    rig.handshake().await;
    // Settle the leg's keying with one RTP packet each way first.
    let probe = g711_rtp(0, 1, 0x0A0A_0A0A, 0x20);
    rig.browser_to_desk(&probe).await;

    // B → A: SRTCP from B's own RTCP port is opened with B's key and sealed for A's association.
    assert!(
        rig.desk_rtcp_to_browser(&receiver_report(0x0B0B_0B0B))
            .await,
        "B's RTCP reaches A"
    );
    // A → B: A's SRTCP arrives on B's RTCP port as SRTCP under the key the engine offered B.
    assert!(
        rig.browser_rtcp_to_desk(&receiver_report(0x0A0A_0A0A), false)
            .await,
        "A's RTCP reaches B's RTCP port"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dtls_caller_toward_an_sdes_callee_leaks_nothing_to_a_stranger_or_before_the_handshake() {
    let mut rig = rig(Shape::same_codec("dtls-sdes-bleed")).await;

    // Before the handshake keys A: the desk phone's media must not reach A in any form.
    for sequence in 0..5u16 {
        let sealed = rig.phone.seal(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0x40));
        rig.desk
            .send_to(&sealed, rig.engine_far)
            .await
            .expect("b send");
    }
    assert!(
        rig.browser_receive(Duration::from_millis(400))
            .await
            .is_none(),
        "no media reaches an unkeyed DTLS caller"
    );
    rig.handshake().await;

    // And nothing A sends toward B before... A cannot send before the handshake: a forged datagram
    // from a stranger source is what is left to try. Establish the legs first.
    let probe = g711_rtp(0, 1, 0x0A0A_0A0A, 0x20);
    rig.browser_to_desk(&probe).await;
    rig.desk_to_browser(&g711_rtp(0, 100, 0x0B0B_0B0B, 0x40))
        .await;

    // A stranger with B's valid SRTP key material, from an address B never signalled, toward A.
    let stranger = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 9), 0))
        .await
        .expect("bind stranger");
    for sequence in 20..25u16 {
        let sealed = rig.phone.seal(&g711_rtp(0, sequence, 0x0C0C_0C0C, 0x40));
        stranger
            .send_to(&sealed, rig.engine_far)
            .await
            .expect("stranger send");
    }
    assert!(
        rig.browser_receive(Duration::from_millis(400))
            .await
            .is_none(),
        "a source B never signalled steals no stream toward A"
    );

    // A stranger replaying the browser's valid SRTP from another address toward B.
    let mut sealed = Vec::new();
    rig.leg()
        .protect(&g711_rtp(0, 30, 0x0A0A_0A0A, 0x20), &mut sealed)
        .expect("browser seals");
    stranger
        .send_to(&sealed, rig.engine_near)
        .await
        .expect("stranger send");
    assert!(
        Rig::desk_receive(&rig.desk, Duration::from_millis(400))
            .await
            .is_none(),
        "a source A never signalled injects nothing toward B"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_keeps_the_dtls_association_and_the_sdes_rollover_of_a_transcrypted_call() {
    let mut rig = rig(Shape::same_codec("dtls-sdes-reoffer")).await;
    rig.handshake().await;
    // Walk A's stream up to the sequence wrap: the engine's SDES leg toward B must continue its own
    // rollover counter (RFC 3711 §3.3.1) across the re-offer, or B (which estimates it for itself)
    // stops authenticating at the wrap.
    for sequence in 65_530..=65_535u16 {
        let packet = g711_rtp(0, sequence, 0x0A0A_0A0A, 0x20);
        assert_eq!(rig.browser_to_desk(&packet).await, packet);
    }

    // A re-offers with the same fingerprint: the association is kept, no new handshake.
    let reoffer = reoffer_from(
        &rig.engine,
        rig.call_id,
        "a",
        caller_sdp(
            rig.addr_a,
            &Shape::same_codec("x"),
            &rig.caller.fingerprint(),
        ),
        far_profile(&Shape::same_codec("x")),
    )
    .await;
    let toward_b = sdp::parse(&ok_sdp_text(&reoffer)).expect("re-offer to B");
    assert!(
        toward_b.secure && !toward_b.dtls,
        "B is re-offered SDES-SRTP"
    );
    let answered = answer_from_b(
        &rig.engine,
        rig.call_id,
        callee_sdp(rig.addr_b, None, &Shape::same_codec("x"), &rig.callee_key),
        ProfileFlags::default(),
    )
    .await;
    assert!(answered.dtls, "A is still answered as a DTLS peer");
    assert_eq!(rig.kind(), PipelineKind::DtlsOffererTranscrypt);

    // Past the wrap, on the same association and the same SDES context at B.
    for sequence in 0..=5u16 {
        let packet = g711_rtp(0, sequence, 0x0A0A_0A0A, 0x21);
        assert_eq!(
            rig.browser_to_desk(&packet).await,
            packet,
            "sequence {sequence} past the wrap authenticates at B"
        );
    }
    let reply = g711_rtp(0, 40, 0x0B0B_0B0B, 0x41);
    assert_eq!(
        rig.desk_to_browser(&reply).await,
        reply,
        "and B's media still reaches A on the kept association"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_fingerprint_on_a_transcrypted_call_runs_a_new_handshake_and_keeps_the_sdes_leg()
{
    let mut rig = rig(Shape::same_codec("dtls-sdes-newcert")).await;
    rig.handshake().await;
    let packet = g711_rtp(0, 100, 0x0A0A_0A0A, 0x20);
    assert_eq!(rig.browser_to_desk(&packet).await, packet);

    // The browser comes back with a new certificate: RFC 8842 §3.1 makes that a new association.
    let renewed = DtlsCertificate::generate().expect("new cert");
    let same = Shape::same_codec("x");
    ok_sdp_text(
        &reoffer_from(
            &rig.engine,
            rig.call_id,
            "a",
            caller_sdp(rig.addr_a, &same, &renewed.fingerprint()),
            far_profile(&same),
        )
        .await,
    );
    let answered = answer_from_b(
        &rig.engine,
        rig.call_id,
        callee_sdp(rig.addr_b, None, &same, &rig.callee_key),
        ProfileFlags::default(),
    )
    .await;
    rig.engine_fingerprint = answered.fingerprint.clone().expect("fingerprint");
    rig.caller = renewed;
    rig.handshake().await;

    // B's SDES stream is the same stream: continuing it needs the leg's state, and B never re-keyed.
    let packet = g711_rtp(0, 101, 0x0A0A_0A0A, 0x22);
    assert_eq!(rig.browser_to_desk(&packet).await, packet);
    let reply = g711_rtp(0, 50, 0x0B0B_0B0B, 0x42);
    assert_eq!(rig.desk_to_browser(&reply).await, reply);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_transcrypted_call_drains_the_bridge_and_its_endpoints() {
    let mut rig = rig(Shape::same_codec("dtls-sdes-delete")).await;
    rig.handshake().await;
    let packet = g711_rtp(0, 1, 0x0A0A_0A0A, 0x20);
    rig.browser_to_desk(&packet).await;
    let endpoints = [rig.engine_near, rig.engine_far];
    let near = rig
        .engine
        .calls
        .get(rig.call_id)
        .map(|call| call.near)
        .expect("near");
    let far = rig
        .engine
        .calls
        .get(rig.call_id)
        .and_then(|call| call.far)
        .expect("far");
    assert!(rig.engine.dtls_bridge().owns(near.rtp.id));
    assert!(rig.engine.dtls_bridge().owns(far.rtp.id));
    assert_eq!(endpoints.len(), 2);

    rig.engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_eq!(rig.engine.session_count(), 0, "the call is gone");
    assert_eq!(
        rig.engine.dtls_bridge().session_count(),
        0,
        "the association's driver is stopped"
    );
    assert!(!rig.engine.dtls_bridge().owns(near.rtp.id));
    assert!(!rig.engine.dtls_bridge().owns(far.rtp.id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_caller_is_transcoded_toward_an_sdes_callee_on_a_different_codec() {
    let mut rig = rig(Shape::transcoded("dtls-sdes-transcode")).await;
    assert_eq!(rig.kind(), PipelineKind::DtlsOffererTranscryptMedia);
    assert!(rig.engine.media().is_media_call(rig.call_id));

    // Unkeyed caller: B's audio must not reach A, in the clear or sealed.
    for sequence in 0..5u16 {
        let sealed = rig.phone.seal(&g711_rtp(8, sequence, 0x0B0B_0B0B, 0xD5));
        rig.desk
            .send_to(&sealed, rig.engine_far)
            .await
            .expect("b send");
    }
    assert!(
        rig.browser_receive(Duration::from_millis(400))
            .await
            .is_none(),
        "nothing reaches the unkeyed DTLS caller"
    );
    rig.handshake().await;

    // A → B: SRTP PCMU in, SRTP PCMA out under the key the engine offered B.
    let mut at_b = None;
    for sequence in 10..60u16 {
        let mut sealed = Vec::new();
        rig.leg()
            .protect(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), &mut sealed)
            .expect("A protects");
        rig.browser
            .send_to(&sealed, rig.engine_near)
            .await
            .expect("a send");
        if let Some(datagram) = Rig::desk_receive(&rig.desk, Duration::from_millis(150)).await {
            at_b = Some(datagram);
            break;
        }
    }
    let datagram = at_b.expect("B receives A's media");
    let opened = rig
        .phone
        .open(&datagram)
        .expect("B opens it under the engine's SDES key");
    assert_eq!(opened[1] & 0x7f, 8, "A's PCMU arrives at B as PCMA");

    // B → A: SRTP PCMA in under B's key, SRTP PCMU out under the handshake's keys.
    let mut at_a = None;
    for sequence in 100..150u16 {
        let sealed = rig.phone.seal(&g711_rtp(8, sequence, 0x0B0B_0B0B, 0xD5));
        rig.desk
            .send_to(&sealed, rig.engine_far)
            .await
            .expect("b send");
        if let Some(datagram) = rig.browser_receive(Duration::from_millis(150)).await {
            let mut plain = Vec::new();
            if rig.leg().unprotect(&datagram, &mut plain).is_ok() {
                at_a = Some(plain);
                break;
            }
        }
    }
    let plain = at_a.expect("A opens B's media");
    assert_eq!(plain[1] & 0x7f, 0, "B's PCMA arrives at A as PCMU");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_opus_browser_is_transcoded_toward_an_sdes_desk_phone_on_pcma_and_g722() {
    use siphon_rtp_codec::factory::{decoder_for, encoder_for};
    if !opus_is_transcodable() {
        return;
    }
    let opus = CodecSpec::new(111, "opus", 48_000, 2, 20);
    for (call_id, desk_codec, flag, rtpmap) in [
        (
            "dtls-sdes-opus-pcma",
            8u8,
            "codec-transcode-PCMA",
            "PCMA/8000",
        ),
        (
            "dtls-sdes-opus-g722",
            9u8,
            "codec-transcode-G722",
            "G722/8000",
        ),
    ] {
        let shape = Shape {
            call_id,
            caller_codec: (111, "opus/48000/2"),
            callee_codec: (desk_codec, rtpmap),
            flags: vec![flag.into()],
            callee_muxes_rtcp: true,
            record: false,
        };
        let mut rig = rig(shape).await;
        assert_eq!(rig.kind(), PipelineKind::DtlsOffererTranscryptMedia);
        rig.handshake().await;
        let mut encoder = encoder_for(&opus).expect("opus encoder");
        let frame = encoder.frame_samples();
        let mut got = None;
        for sequence in 0..120u16 {
            let tone: Vec<i16> = (0..frame)
                .map(|index| {
                    let time = (usize::from(sequence) * frame + index) as f64 / 48_000.0;
                    (8000.0 * (2.0 * std::f64::consts::PI * 440.0 * time).sin()) as i16
                })
                .collect();
            let mut payload = [0u8; 512];
            let written = encoder.encode(&tone, &mut payload).expect("encode");
            let mut packet = vec![0x80, 111];
            packet.extend_from_slice(&sequence.to_be_bytes());
            packet.extend_from_slice(&(u32::from(sequence) * 960).to_be_bytes());
            packet.extend_from_slice(&0x0A0A_0A0Au32.to_be_bytes());
            packet.extend_from_slice(&payload[..written]);
            let mut sealed = Vec::new();
            rig.leg().protect(&packet, &mut sealed).expect("A protects");
            rig.browser
                .send_to(&sealed, rig.engine_near)
                .await
                .expect("a send");
            if let Some(datagram) = Rig::desk_receive(&rig.desk, Duration::from_millis(30)).await {
                got = rig.phone.open(&datagram);
                if got.is_some() {
                    break;
                }
            }
        }
        let opened = got.expect("the desk phone receives the browser's Opus, transcoded");
        assert_eq!(
            opened[1] & 0x7f,
            desk_codec,
            "{call_id}: Opus arrives at the desk phone as the codec it answered"
        );

        // And back: the desk phone's codec reaches the browser as Opus the browser decodes.
        let mut decoder = decoder_for(&opus).expect("opus decoder");
        let mut heard = false;
        for sequence in 200..320u16 {
            let sealed = rig
                .phone
                .seal(&g711_rtp(desk_codec, sequence, 0x0B0B_0B0B, 0xD5));
            rig.desk
                .send_to(&sealed, rig.engine_far)
                .await
                .expect("b send");
            if let Some(datagram) = rig.browser_receive(Duration::from_millis(30)).await {
                let mut plain = Vec::new();
                if rig.leg().unprotect(&datagram, &mut plain).is_ok() {
                    assert_eq!(plain[1] & 0x7f, 111, "{call_id}: the browser receives Opus");
                    let mut pcm = vec![0i16; 5760];
                    decoder
                        .decode(&plain[12..], &mut pcm)
                        .expect("the browser decodes it");
                    heard = true;
                    break;
                }
            }
        }
        assert!(heard, "{call_id}: the browser hears the desk phone");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_transcoded_twin_carries_the_desk_phones_separate_rtcp_port_both_ways() {
    let mut shape = Shape::transcoded("dtls-sdes-transcode-rtcp");
    shape.callee_muxes_rtcp = false;
    let mut rig = rig(shape).await;
    assert_eq!(rig.kind(), PipelineKind::DtlsOffererTranscryptMedia);
    rig.handshake().await;
    // Key the actor's legs with one packet each way.
    let mut warmed = false;
    for sequence in 10..60u16 {
        let mut sealed = Vec::new();
        rig.leg()
            .protect(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), &mut sealed)
            .expect("A protects");
        rig.browser
            .send_to(&sealed, rig.engine_near)
            .await
            .expect("a send");
        if Rig::desk_receive(&rig.desk, Duration::from_millis(150))
            .await
            .is_some()
        {
            warmed = true;
            break;
        }
    }
    assert!(warmed, "the pipeline is keyed");

    // B → A over B's own RTCP port, and A's multiplexed SRTCP to it.
    assert!(
        rig.desk_rtcp_to_browser(&receiver_report(0x0B0B_0B0B))
            .await,
        "B's RTCP reaches A"
    );
    assert!(
        rig.browser_rtcp_to_desk(&receiver_report(0x0A0A_0A0A), true)
            .await,
        "A's RTCP reaches B's RTCP port"
    );
}

#[tokio::test]
async fn a_dtls_caller_toward_an_sdes_callee_is_offered_and_answered_by_the_negotiated_posture() {
    // The offer is accepted (it used to be refused as `secure-offerer-unsupported`), and a DTLS
    // callee on top of a DTLS caller stays refused: that would be two associations.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let caller = DtlsCertificate::generate().expect("caller cert");
    let shape = Shape::same_codec("posture");
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtls-sdes-posture".into(),
                from_tag: "a".into(),
                sdp: caller_sdp(addr_a, &shape, &caller.fingerprint()),
                profile: far_profile(&shape),
            },
        )
        .await;
    let text = ok_sdp_text(&offer);
    let toward_b = sdp::parse(&text).expect("far offer");
    assert!(
        toward_b.secure && !toward_b.dtls && toward_b.crypto.len() == 1,
        "SDES toward B: {text}"
    );
    assert!(text.contains("RTP/SAVP"), "{text}");
    assert!(
        !text.contains("a=fingerprint"),
        "A's keying is not B's: {text}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transcrypted_call_is_refused_a_split_and_a_seat_by_name_not_answered_ok_and_ignored() {
    // The bridge holds the DTLS leg and the SDES leg apart, and a hold or a seat moves one leg's
    // crypto into another owner: the call is refused, by a token the controller can match on, rather
    // than answered `ok` with the other leg left unkeyed.
    for (call_id, shape) in [
        (
            "dtls-sdes-refuse-relay",
            Shape::same_codec("dtls-sdes-refuse-relay"),
        ),
        (
            "dtls-sdes-refuse-twin",
            Shape::transcoded("dtls-sdes-refuse-twin"),
        ),
    ] {
        let mut rig = rig(shape).await;
        rig.handshake().await;
        let seat = rig
            .engine
            .handle(
                CLIENT,
                Command::ConferenceSeat {
                    call_id: call_id.into(),
                    from_tag: "a".into(),
                    conference_id: "room".into(),
                    role: siphon_rtp_proto::ConferenceRole::Talker,
                    dtmf: siphon_rtp_proto::ConferenceDtmf::Events,
                },
            )
            .await;
        match seat {
            CmdResult::Error { reason } => assert!(
                reason.contains("secure-transcrypt-seat-unsupported"),
                "{call_id}: {reason}"
            ),
            other => panic!("{call_id}: a seat must be refused, got {other:?}"),
        }
        {
            let split = rig
                .engine
                .handle(
                    CLIENT,
                    Command::AttachWsSplit(siphon_rtp_proto::WsSplitAttach {
                        call_id: call_id.into(),
                        from_tag: "a".into(),
                        ws_uri: "ws://127.0.0.1:9/bot".into(),
                        sample_rate: None,
                        offerer_profile: None,
                        answerer_profile: None,
                    }),
                )
                .await;
            match split {
                CmdResult::Error { reason } => assert!(
                    reason.contains("secure-transcrypt-hold-unsupported"),
                    "{call_id}: {reason}"
                ),
                other => panic!("{call_id}: a split must be refused, got {other:?}"),
            }
        }
        // The refusal changed nothing: the call still relays.
        let packet = g711_rtp(0, 5, 0x0A0A_0A0A, 0x20);
        let heard = if rig.kind() == PipelineKind::DtlsOffererTranscrypt {
            rig.browser_to_desk(&packet).await
        } else {
            packet.clone()
        };
        assert_eq!(heard.len(), packet.len(), "{call_id}: media still flows");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_answer_with_the_same_sdes_key_under_a_new_tag_keeps_the_replay_window() {
    // RFC 3711 §3.3.2 / §3.4: the replay state belongs to the key, not to the `a=crypto` tag. A
    // re-answer that repeats B's master key and salt under another tag must keep the leg, or a
    // replayed SRTCP packet authenticates again and is sealed anew for A (its outbound index is
    // fresh, so nothing downstream would stop it).
    let mut rig = rig(Shape::same_codec("dtls-sdes-retag")).await;
    rig.handshake().await;
    rig.desk_to_browser(&g711_rtp(0, 300, 0x0B0B_0B0B, 0x40))
        .await;
    let mut first = Vec::new();
    rig.phone
        .sends_rtcp
        .protect(&receiver_report(0x0B0B_0B0B), &mut first)
        .expect("seal");
    let mut second = Vec::new();
    rig.phone
        .sends_rtcp
        .protect(&receiver_report(0x0B0B_0B0B), &mut second)
        .expect("seal");
    for datagram in [&first, &second] {
        rig.desk
            .send_to(datagram, rig.engine_far)
            .await
            .expect("send");
        assert!(
            rig.browser_receive(Duration::from_millis(400))
                .await
                .is_some(),
            "the report reaches A"
        );
    }

    let same = Shape::same_codec("x");
    ok_sdp_text(
        &reoffer_from(
            &rig.engine,
            rig.call_id,
            "a",
            caller_sdp(rig.addr_a, &same, &rig.caller.fingerprint()),
            far_profile(&same),
        )
        .await,
    );
    let mut retagged = rig.callee_key;
    retagged.tag = 2;
    answer_from_b(
        &rig.engine,
        rig.call_id,
        callee_sdp(rig.addr_b, None, &same, &retagged),
        ProfileFlags::default(),
    )
    .await;
    // The first report is behind the highest index, inside the window: only the bitmap knows it.
    rig.desk
        .send_to(&first, rig.engine_far)
        .await
        .expect("replay");
    assert!(
        rig.browser_receive(Duration::from_millis(400))
            .await
            .is_none(),
        "a replayed SRTCP packet is still dropped after the tag changed"
    );
}

/// What the call record says about A's leg and the media path, to compare before and after a refused
/// answer: nothing in it may have moved.
fn record(rig: &Rig) -> String {
    let call = rig.engine.calls.get(rig.call_id).expect("call");
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        call.pipeline,
        call.near.remote_rtp,
        call.near_dtls,
        call.near_remote_ice,
        call.near_direction,
        call.near_offered_codecs,
        call.far_remote_crypto,
    )
}

/// Re-offer from A on an unchanged association and answer from B under `answer_profile` and `answer`.
/// Returns the call record as the re-offer left it, and the answer's result.
async fn renegotiate(
    rig: &Rig,
    answer: String,
    answer_profile: ProfileFlags,
) -> (String, CmdResult) {
    let same = Shape::same_codec("x");
    ok_sdp_text(
        &reoffer_from(
            &rig.engine,
            rig.call_id,
            "a",
            caller_sdp(rig.addr_a, &same, &rig.caller.fingerprint()),
            far_profile(&same),
        )
        .await,
    );
    let before = record(rig);
    let result = rig
        .engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: rig.call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer,
                profile: answer_profile,
            },
        )
        .await;
    (before, result)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_call_re_answered_into_the_transcode_twin_is_refused_by_name_and_keeps_relaying() {
    let mut rig = rig(Shape::same_codec("dtls-sdes-to-twin")).await;
    rig.handshake().await;
    let packet = g711_rtp(0, 1, 0x0A0A_0A0A, 0x20);
    assert_eq!(rig.browser_to_desk(&packet).await, packet);
    let same = Shape::same_codec("x");
    let (before, answer) = renegotiate(
        &rig,
        callee_sdp(rig.addr_b, None, &same, &rig.callee_key),
        ProfileFlags {
            noise_suppression: true,
            ..Default::default()
        },
    )
    .await;
    match answer {
        CmdResult::Error { reason } => assert!(
            reason.contains("secure-transcrypt-renegotiation-unsupported"),
            "{reason}"
        ),
        other => panic!("the switch must be refused, not answered ok: {other:?}"),
    }
    assert_eq!(rig.kind(), PipelineKind::DtlsOffererTranscrypt);
    assert_eq!(before, record(&rig), "the call record is untouched");
    let next = g711_rtp(0, 2, 0x0A0A_0A0A, 0x21);
    assert_eq!(
        rig.browser_to_desk(&next).await,
        next,
        "the live call is untouched"
    );
    let reply = g711_rtp(0, 3, 0x0B0B_0B0B, 0x41);
    assert_eq!(rig.desk_to_browser(&reply).await, reply);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transcode_twin_re_answered_into_the_relay_is_refused_by_name_and_keeps_its_association()
{
    let mut rig = rig(Shape::transcoded("dtls-sdes-to-relay")).await;
    rig.handshake().await;
    let mut warmed = false;
    for sequence in 10..60u16 {
        let mut sealed = Vec::new();
        rig.leg()
            .protect(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), &mut sealed)
            .expect("seal");
        rig.browser
            .send_to(&sealed, rig.engine_near)
            .await
            .expect("send");
        if Rig::desk_receive(&rig.desk, Duration::from_millis(150))
            .await
            .is_some()
        {
            warmed = true;
            break;
        }
    }
    assert!(warmed, "the twin is keyed");
    // B now answers the codec A speaks and nothing needs the audio: the answer resolves to the relay.
    let same = Shape::same_codec("x");
    let (before, answer) = renegotiate(
        &rig,
        callee_sdp(rig.addr_b, Some(rig.addr_b), &same, &rig.callee_key)
            .replace("a=rtcp:", "a=rtcp-mux\r\na=ignored:"),
        ProfileFlags::default(),
    )
    .await;
    match answer {
        CmdResult::Error { reason } => assert!(
            reason.contains("secure-transcrypt-renegotiation-unsupported"),
            "{reason}"
        ),
        other => panic!("the switch must be refused, not answered ok: {other:?}"),
    }
    assert!(
        rig.engine.dtls_bridge().session_count() == 1,
        "the live association is not torn down by the refusal"
    );
    assert_eq!(rig.kind(), PipelineKind::DtlsOffererTranscryptMedia);
    assert_eq!(before, record(&rig), "the call record is untouched");
    // The live call still carries audio both ways, transcoded as before.
    let mut at_b = None;
    for sequence in 100..150u16 {
        let mut sealed = Vec::new();
        rig.leg()
            .protect(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), &mut sealed)
            .expect("seal");
        rig.browser
            .send_to(&sealed, rig.engine_near)
            .await
            .expect("send");
        if let Some(datagram) = Rig::desk_receive(&rig.desk, Duration::from_millis(150)).await {
            at_b = rig.phone.open(&datagram);
            break;
        }
    }
    assert_eq!(at_b.expect("A still reaches B")[1] & 0x7f, 8);
    let mut at_a = false;
    for sequence in 200..250u16 {
        let sealed = rig.phone.seal(&g711_rtp(8, sequence, 0x0B0B_0B0B, 0xD5));
        rig.desk
            .send_to(&sealed, rig.engine_far)
            .await
            .expect("send");
        if rig
            .browser_receive(Duration::from_millis(150))
            .await
            .is_some()
        {
            at_a = true;
            break;
        }
    }
    assert!(at_a, "B still reaches A");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_switch_is_refused_before_anything_changes_when_the_caller_answers_the_callees_re_offer(
) {
    // The reversed exchange writes A's answer onto the call record before the media path is chosen,
    // so the refusal has to come ahead of those writes: addresses, direction and ICE credentials of A
    // must stay what they were.
    let mut rig = rig(Shape::same_codec("dtls-sdes-reversed")).await;
    rig.handshake().await;
    let packet = g711_rtp(0, 1, 0x0A0A_0A0A, 0x20);
    assert_eq!(rig.browser_to_desk(&packet).await, packet);
    let same = Shape::same_codec("x");
    ok_sdp_text(
        &reoffer_from(
            &rig.engine,
            rig.call_id,
            "b",
            callee_sdp(rig.addr_b, None, &same, &rig.callee_key),
            ProfileFlags::default(),
        )
        .await,
    );
    let before = record(&rig);
    let moved = SocketAddr::new(rig.addr_a.ip(), rig.addr_a.port().wrapping_add(2));
    let hex = rig
        .caller
        .fingerprint()
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let a_answer = format!(
        "v=0\r\no=- 1 2 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         a=sendonly\r\na=ice-ufrag:abcd\r\na=ice-pwd:abcdefghijklmnopqrstuv\r\n\
         a=setup:active\r\na=fingerprint:{hash} {hex}\r\n",
        ip = moved.ip(),
        port = moved.port(),
        hash = rig.caller.fingerprint().hash_function,
    );
    let answer = rig
        .engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: rig.call_id.into(),
                from_tag: "b".into(),
                to_tag: "a".into(),
                sdp: a_answer,
                profile: ProfileFlags {
                    noise_suppression: true,
                    ..Default::default()
                },
            },
        )
        .await;
    match answer {
        CmdResult::Error { reason } => assert!(
            reason.contains("secure-transcrypt-renegotiation-unsupported"),
            "{reason}"
        ),
        other => panic!("the switch must be refused, not answered ok: {other:?}"),
    }
    assert_eq!(
        before,
        record(&rig),
        "A's answer was not written to the call"
    );
    let next = g711_rtp(0, 2, 0x0A0A_0A0A, 0x21);
    assert_eq!(rig.browser_to_desk(&next).await, next);
    let reply = g711_rtp(0, 3, 0x0B0B_0B0B, 0x41);
    assert_eq!(rig.desk_to_browser(&reply).await, reply);
}
