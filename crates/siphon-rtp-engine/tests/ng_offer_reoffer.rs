//! An rtpengine NG `offer` on a call that is already live is a re-offer, not a new call.
//!
//! A SIP proxy speaking NG sends `offer` again for every re-INVITE (hold, resume, session refresh).
//! Replacing the call on each one moved the engine ports under the peers and cost an interception its
//! delivery connection. These tests drive the NG entry (`handle_ng`) over the UDP-loopback datapath
//! against a stub Mediation Function, and pin what stays replace: a codec change, an unknown
//! from-tag, and the JSON `offer`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test harness: a panic reports failure"
)]

mod common;

use std::net::SocketAddr;

use common::x3_mdf::{acceptor, attribute, pki, read_pdus, rtp, Pki, CORRELATION_ID, SHORT};
use siphon_rtp_datapath::Datapath as _;
use siphon_rtp_engine::srtp_bridge::run_redirect_dispatcher;
use siphon_rtp_engine::{ClientId, Engine};
use siphon_rtp_li::attributes::attribute_type;
use siphon_rtp_proto::{CmdResult, Command, Event, ProfileFlags, X3EndReason, X3TargetLeg, Xid};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

type Datapath = siphon_rtp_datapath::udp::UdpLoopbackDatapath;

const CLIENT: ClientId = ClientId(1);
const XID_TEXT: &str = "8c292fa1-5831-46ec-86be-bd85f2083299";
const CALL: &str = "ng-reoffer";

struct Rig {
    engine: Engine<Datapath>,
    pki: Pki,
    listener: TcpListener,
    events: flume::Receiver<Event>,
    phone_a: UdpSocket,
    phone_b: UdpSocket,
}

fn sdp_of(result: &CmdResult) -> String {
    match result {
        CmdResult::Ok {
            sdp: Some(text), ..
        } => text.clone(),
        other => panic!("expected Ok with sdp, got {other:?}"),
    }
}

fn address_of(result: &CmdResult) -> SocketAddr {
    siphon_rtp_engine::sdp::parse(&sdp_of(result))
        .expect("parse the engine's sdp")
        .remote_rtp
}

/// A plain `RTP/AVP` session description for one phone offering `codecs` (payload type, name).
fn sdp(address: SocketAddr, codecs: &[(u8, &str)]) -> String {
    let types: Vec<String> = codecs
        .iter()
        .map(|(number, _)| number.to_string())
        .collect();
    let maps: String = codecs
        .iter()
        .map(|(number, name)| format!("a=rtpmap:{number} {name}/8000\r\n"))
        .collect();
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} RTP/AVP {types}\r\n{maps}a=rtcp-mux\r\na=sendrecv\r\n",
        ip = address.ip(),
        port = address.port(),
        types = types.join(" "),
    )
}

const PCMU: &[(u8, &str)] = &[(0, "PCMU")];
const PCMA: &[(u8, &str)] = &[(8, "PCMA")];

impl Rig {
    async fn new() -> Self {
        let pki = pki();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mdf");
        let engine = Engine::new(Datapath::new()).with_x3(pki.config.clone());
        tokio::spawn(run_redirect_dispatcher(
            engine.datapath().rx(),
            engine.bridge(),
            engine.media(),
            engine.ws(),
            engine.conference(),
            None,
        ));
        let (_generation, events) = engine.register_client_generation(CLIENT);
        Self {
            engine,
            pki,
            listener,
            events,
            phone_a: UdpSocket::bind("127.0.0.2:0").await.expect("bind a"),
            phone_b: UdpSocket::bind("127.0.0.3:0").await.expect("bind b"),
        }
    }

    fn addr_a(&self) -> SocketAddr {
        self.phone_a.local_addr().expect("a addr")
    }

    fn addr_b(&self) -> SocketAddr {
        self.phone_b.local_addr().expect("b addr")
    }

    fn offer_command(&self, from_tag: &str, sdp: String) -> Command {
        Command::Offer {
            call_id: CALL.into(),
            from_tag: from_tag.into(),
            sdp,
            profile: ProfileFlags::default(),
        }
    }

    /// The NG `offer` from A, and the address the engine presents toward B.
    async fn ng_offer(&self, from_tag: &str, sdp: String) -> CmdResult {
        self.engine
            .handle_ng(CLIENT, self.offer_command(from_tag, sdp))
            .await
    }

    async fn ng_answer(&self, from_tag: &str, to_tag: &str, sdp: String) -> CmdResult {
        self.engine
            .handle_ng(
                CLIENT,
                Command::Answer {
                    call_id: CALL.into(),
                    from_tag: from_tag.into(),
                    to_tag: to_tag.into(),
                    sdp,
                    profile: ProfileFlags::default(),
                },
            )
            .await
    }

    /// A normal call: offer from A, answer from B. Returns (toward B, toward A).
    async fn established(&self) -> (SocketAddr, SocketAddr) {
        let toward_b = address_of(&self.ng_offer("tag-a", sdp(self.addr_a(), PCMU)).await);
        let answered = self
            .ng_answer("tag-a", "tag-b", sdp(self.addr_b(), PCMU))
            .await;
        (toward_b, address_of(&answered))
    }

    async fn attach(&self) {
        let result = self
            .engine
            .handle(
                CLIENT,
                Command::AttachX3 {
                    call_id: CALL.into(),
                    from_tag: "tag-a".into(),
                    delivery: self.listener.local_addr().expect("mdf addr").to_string(),
                    xid: XID_TEXT.parse::<Xid>().expect("xid"),
                    correlation_id: CORRELATION_ID,
                    target_leg: X3TargetLeg::Caller,
                },
            )
            .await;
        assert!(matches!(result, CmdResult::Ok { .. }), "attach: {result:?}");
    }

    async fn accept(&self) -> tokio_rustls::server::TlsStream<tokio::net::TcpStream> {
        let acceptor = acceptor(&self.pki);
        let (stream, _) = timeout(SHORT, self.listener.accept())
            .await
            .expect("the engine connects to the mediation function")
            .expect("accept");
        timeout(SHORT, acceptor.accept(stream))
            .await
            .expect("no timeout")
            .expect("mutual TLS handshake")
    }

    fn x3_end_reasons(&self) -> Vec<X3EndReason> {
        self.events
            .try_iter()
            .filter_map(|event| match event {
                Event::X3Ended { reason, .. } => Some(reason),
                _ => None,
            })
            .collect()
    }

    /// Send one packet from A and read the PDU it produces, returning the delivery sequence.
    async fn a_delivers<S: tokio::io::AsyncRead + Unpin>(
        &self,
        tls: &mut S,
        toward_a: SocketAddr,
        rtp_sequence: u16,
    ) -> u32 {
        self.phone_a
            .send_to(&rtp(rtp_sequence), toward_a)
            .await
            .expect("a sends");
        let pdus = read_pdus(tls, 1).await;
        assert_eq!(pdus[0].header.correlation_id, CORRELATION_ID, "same CID");
        let value = attribute(&pdus[0].attributes, attribute_type::SEQUENCE_NUMBER).expect("seq");
        u32::from_be_bytes([value[0], value[1], value[2], value[3]])
    }

    /// Media really flows: a packet from A arrives at B, and one from B at A.
    async fn assert_relays(&self, toward_a: SocketAddr, toward_b: SocketAddr, base: u16) {
        let mut buffer = [0u8; 2048];
        self.phone_a
            .send_to(&rtp(base), toward_a)
            .await
            .expect("a sends");
        timeout(SHORT, self.phone_b.recv_from(&mut buffer))
            .await
            .expect("A's packet reaches B")
            .expect("recv");
        self.phone_b
            .send_to(&rtp(base + 1000), toward_b)
            .await
            .expect("b sends");
        timeout(SHORT, self.phone_a.recv_from(&mut buffer))
            .await
            .expect("B's packet reaches A")
            .expect("recv");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ng_offer_on_a_live_call_keeps_its_ports_and_media_flows() {
    let rig = Rig::new().await;
    let (toward_b, toward_a) = rig.established().await;

    let reoffered = rig.ng_offer("tag-a", sdp(rig.addr_a(), PCMU)).await;
    assert_eq!(
        address_of(&reoffered),
        toward_b,
        "the far port did not move"
    );
    let answered = rig
        .ng_answer("tag-a", "tag-b", sdp(rig.addr_b(), PCMU))
        .await;
    assert_eq!(
        address_of(&answered),
        toward_a,
        "the near port did not move"
    );

    rig.assert_relays(toward_a, toward_b, 1).await;
    // A replace would have ended the call (CDR reason "replaced") and freed these ports.
    let deleted = rig
        .engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: CALL.into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(deleted, CmdResult::Ok { .. }),
        "the call survived: {deleted:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn x3_survives_an_ng_re_offer_and_its_answer_with_one_sequence() {
    let rig = Rig::new().await;
    let (_, toward_a) = rig.established().await;
    rig.attach().await;
    let mut tls = rig.accept().await;
    assert_eq!(rig.a_delivers(&mut tls, toward_a, 1).await, 0);

    rig.ng_offer("tag-a", sdp(rig.addr_a(), PCMU)).await;
    rig.ng_answer("tag-a", "tag-b", sdp(rig.addr_b(), PCMU))
        .await;

    assert_eq!(
        rig.a_delivers(&mut tls, toward_a, 2).await,
        1,
        "the delivery connection's sequence continues"
    );
    assert!(rig.x3_end_reasons().is_empty(), "the interception goes on");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ng_re_offer_from_b_is_completed_by_the_answer_with_reversed_tags() {
    let rig = Rig::new().await;
    let (toward_b, toward_a) = rig.established().await;
    rig.attach().await;
    let mut tls = rig.accept().await;
    assert_eq!(rig.a_delivers(&mut tls, toward_a, 1).await, 0);

    // B re-offers (NG: from-tag is B's); the engine presents its near leg to A, on the same port.
    let reoffered = rig.ng_offer("tag-b", sdp(rig.addr_b(), PCMU)).await;
    assert_eq!(
        address_of(&reoffered),
        toward_a,
        "B's re-offer keeps the ports"
    );
    // A answers: NG carries the offerer's tag as from-tag and the answerer's as to-tag.
    let answered = rig
        .ng_answer("tag-b", "tag-a", sdp(rig.addr_a(), PCMU))
        .await;
    assert!(
        matches!(answered, CmdResult::Ok { .. }),
        "answer: {answered:?}"
    );
    assert_eq!(address_of(&answered), toward_b);

    rig.assert_relays(toward_a, toward_b, 10).await;
    assert!(rig.x3_end_reasons().is_empty(), "the interception goes on");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_codec_change_ng_re_offer_falls_back_to_replace_and_ends_the_interception() {
    let rig = Rig::new().await;
    let (toward_b, _) = rig.established().await;
    rig.attach().await;
    let _tls = rig.accept().await;

    let replaced = rig.ng_offer("tag-a", sdp(rig.addr_a(), PCMA)).await;
    assert!(matches!(replaced, CmdResult::Ok { .. }), "{replaced:?}");
    assert_ne!(address_of(&replaced), toward_b, "a replace binds new ports");
    assert_eq!(rig.x3_end_reasons(), vec![X3EndReason::CallEnded]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ng_offer_with_an_unknown_from_tag_still_replaces_the_call() {
    let rig = Rig::new().await;
    let (toward_b, _) = rig.established().await;
    rig.attach().await;
    let _tls = rig.accept().await;

    let replaced = rig.ng_offer("tag-other", sdp(rig.addr_a(), PCMU)).await;
    assert_ne!(address_of(&replaced), toward_b, "a replace binds new ports");
    assert_eq!(rig.x3_end_reasons(), vec![X3EndReason::CallEnded]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_json_offer_on_a_live_call_still_replaces_it() {
    let rig = Rig::new().await;
    let (toward_b, _) = rig.established().await;
    rig.attach().await;
    let _tls = rig.accept().await;

    let replaced = rig
        .engine
        .handle(CLIENT, rig.offer_command("tag-a", sdp(rig.addr_a(), PCMU)))
        .await;
    assert_ne!(address_of(&replaced), toward_b, "a replace binds new ports");
    assert_eq!(rig.x3_end_reasons(), vec![X3EndReason::CallEnded]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ng_offer_repeated_before_the_answer_keeps_its_ports_and_still_answers() {
    // A proxy retransmits or re-sends `offer` while the callee has not answered yet.
    let rig = Rig::new().await;
    let toward_b = address_of(&rig.ng_offer("tag-a", sdp(rig.addr_a(), PCMU)).await);
    let again = rig.ng_offer("tag-a", sdp(rig.addr_a(), PCMU)).await;
    assert_eq!(address_of(&again), toward_b, "the far port did not move");
    let answered = rig
        .ng_answer("tag-a", "tag-b", sdp(rig.addr_b(), PCMU))
        .await;
    rig.assert_relays(address_of(&answered), toward_b, 1).await;
}
