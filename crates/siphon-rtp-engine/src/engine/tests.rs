#![cfg(test)]

use dashmap::DashMap;
use siphon_rtp_codec::factory::{self, CodecSpec, OPUS_MAX_PTIME_MS};
use siphon_rtp_datapath::udp::UdpLoopbackDatapath;
use siphon_rtp_datapath::{
    AddressFamily, Endpoint, EndpointId, FlowAction, IceConfig, ObservedRtcp,
};
use siphon_rtp_hep::exporter::HepExporter;
use siphon_rtp_hep::protocol_type;
use siphon_rtp_proto::{
    BridgeDirection, CmdResult, Command, ConferenceRole, EngineStatistics, Event,
    MediaTimeoutReason, PlayMediaSource, PlayRepeat, ProfileFlags, SessionStats, WsBridgeEndReason,
    WsTeeDirection, WsVadEngine,
};
use siphon_rtp_srtp::leg::SecureLeg;
use siphon_rtp_srtp::sdes::{CryptoAttribute, CryptoSuite};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::interface::InterfaceTable;
use crate::sdp;

use super::admin::{opus_is_transcodable, supported_codecs};
use super::answer::{
    negotiated_near_codec, parse_ptime_override, with_ptime_override, MAX_PTIME_OVERRIDE_MS,
};
use super::answer_local::{resolve_offerer_security, WsTakeoverSecurity};
use super::dispatch::{command_call_id, is_chatty_command};
use super::inject::resolve_toward_a;
use super::negotiate::{
    apply_replace_directives, parse_codec_flags, same_codec, transcode_codec_spec,
    OPUS_DYNAMIC_PAYLOAD_TYPE,
};
use super::offer::far_address_family;
use super::snapshot::{codec_snapshot, restore_codec};
use super::takeover::{WsVadConfig, DEFAULT_WS_VAD_HANGOVER_MS, DEFAULT_WS_VAD_THRESHOLD};
use super::telemetry::{qos_captures, qos_quality_events, rtcp_capture};
use super::*;

/// The default control client for tests that don't exercise per-client isolation.
const CLIENT: ClientId = ClientId(1);

#[test]
fn ws_vad_config_is_absent_unless_vad_or_barge_in_is_requested() {
    assert!(WsVadConfig::from_profile(&ProfileFlags::default()).is_none());
    // Setting only the tuning knobs is not a request for a detector.
    let tuned = ProfileFlags {
        ws_vad_engine: Some(WsVadEngine::Neural),
        ws_vad_min_speech_ms: Some(100),
        ..Default::default()
    };
    assert!(WsVadConfig::from_profile(&tuned).is_none());
    // Barge-in implies VAD.
    let barge = ProfileFlags {
        ws_barge_in: true,
        ..Default::default()
    };
    assert!(WsVadConfig::from_profile(&barge).is_some());
}

#[test]
fn ws_vad_config_defaults_to_the_energy_detector_with_no_leading_run() {
    let profile = ProfileFlags {
        ws_vad: true,
        ..Default::default()
    };
    let config = WsVadConfig::from_profile(&profile).expect("requested");
    assert_eq!(config.engine, WsVadEngine::Energy);
    assert_eq!(config.threshold, DEFAULT_WS_VAD_THRESHOLD);
    assert_eq!(config.hangover_ms, DEFAULT_WS_VAD_HANGOVER_MS);
    assert_eq!(config.minimum_speech_ms, 0);
    // 200 ms of hangover at a 20 ms ptime is 10 frames; no leading run is one frame.
    assert_eq!(config.hangover_frames(20), 10);
    assert_eq!(config.minimum_speech_frames(20), 1);
    assert!(!config
        .build_detector(8_000, 20)
        .expect("energy is infallible")
        .is_neural());
}

#[test]
fn build_detector_converts_the_hangover_at_the_ptime_it_is_given() {
    // Scope, stated plainly because it is easy to overclaim here: this covers
    // `build_detector`'s **conversion** — the detector it returns holds speech for
    // `hangover_ms / ptime_ms` frames — and nothing else. The ptime is a literal, so this can
    // say nothing about whether the engine hands the helper the leg's real ptime.
    //
    // That wiring is where the 0.3.0 regression lived (the call site passed a hard-coded 1 ms,
    // so a 300 ms hangover became 300 frames and `speech_stopped` never arrived), and it is
    // covered end to end by
    // `a_ws_takeover_leg_reaches_the_turn_endpoint_within_the_configured_hangover`.
    let profile = ProfileFlags {
        ws_vad: true,
        ws_vad_hangover_ms: Some(300),
        ..Default::default()
    };
    let config = WsVadConfig::from_profile(&profile).expect("requested");
    let mut detector = config
        .build_detector(8_000, 20)
        .expect("energy is infallible");

    // 20 ms at 8 kHz. Mean-square energy of the loud frame is 16e6, well over the 1e6 default.
    let loud: Vec<i16> = (0..160)
        .map(|index| if index % 2 == 0 { 4_000 } else { -4_000 })
        .collect();
    let silence = [0i16; 160];

    assert!(detector.is_speech(&loud), "a loud frame is speech");
    // 300 ms of hangover at a 20 ms ptime is 15 frames, so silence still reads as speech
    // through the fifteenth …
    for frame in 1..=15 {
        assert!(
            detector.is_speech(&silence),
            "the hangover expired {frame} frames in; it should hold 15"
        );
    }
    // … and the sixteenth is the turn endpoint, 320 ms after the last loud frame.
    assert!(
        !detector.is_speech(&silence),
        "the detector held speech past 15 frames, so it was not built with hangover_ms / ptime_ms"
    );
}

#[test]
fn ws_vad_config_selects_the_neural_detector_and_the_leading_run() {
    let profile = ProfileFlags {
        ws_vad: true,
        ws_barge_in: true,
        ws_vad_engine: Some(WsVadEngine::Neural),
        ws_vad_min_speech_ms: Some(100),
        ..Default::default()
    };
    let config = WsVadConfig::from_profile(&profile).expect("requested");
    assert_eq!(config.engine, WsVadEngine::Neural);
    assert!(config.barge_in);
    // The run is carried in ms and rounded **up** to whole ptime frames — under-delivering on a
    // debounce is the failure that matters.
    assert_eq!(config.minimum_speech_frames(20), 5);
    assert_eq!(config.minimum_speech_frames(30), 4);
    // Both telephony rates build; the narrowband leg is resampled into the detector.
    for rate in [8_000u32, 16_000] {
        assert!(config
            .build_detector(rate, 20)
            .expect("neural builds for a telephony rate")
            .is_neural());
    }
}

#[test]
fn a_neural_detector_that_cannot_be_built_fails_the_bridge_rather_than_downgrading() {
    // A controller asking for the neural detector did so to stop barge-in firing on noise;
    // handing back the energy gate it was avoiding would look like success and behave like the
    // bug. `setup_ws_bridge` propagates this reason out of `Command::Offer` as an error result.
    let profile = ProfileFlags {
        ws_vad: true,
        ws_vad_engine: Some(WsVadEngine::Neural),
        ..Default::default()
    };
    let config = WsVadConfig::from_profile(&profile).expect("requested");
    let error = config
        .build_detector(0, 20)
        .expect_err("a zero rate is refused");
    assert!(
        error.contains("neural VAD unavailable"),
        "unhelpful reason: {error}"
    );
}

async fn phone() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = socket.local_addr().expect("addr");
    (socket, addr)
}

#[test]
fn codec_snapshot_round_trips_the_opus_fmtp_parameters() {
    // A checkpoint/restore must not lose negotiated Opus parameters: the restored leg has to keep
    // the same channel layout (`sprop-stereo`), packetization ceiling (`maxptime`), and
    // rate-control / FEC / DTX limits, or the standby re-encodes outside what the peer accepted.
    let params = siphon_rtp_codec::factory::OpusParams {
        max_average_bitrate: Some(24_000),
        max_playback_rate_hz: 16_000,
        max_ptime_ms: 40,
        stereo: true,
        sprop_stereo: true,
        cbr: true,
        use_inband_fec: true,
        use_dtx: true,
    };
    let original = CodecSpec::new(111, "opus", 48_000, 2, 40).with_opus_params(Some(params));
    let snapshot = codec_snapshot(&original);
    // Through JSON, exactly as `checkpoint` → `restore` carries it.
    let json = serde_json::to_string(&snapshot).expect("serialize");
    let decoded: crate::ha::CodecSnapshot = serde_json::from_str(&json).expect("deserialize");
    let restored = restore_codec(&decoded);
    assert_eq!(restored, original);
    assert_eq!(restored.opus_params(), params);
    // …and the derived behaviour survives with it.
    assert_eq!(restored.decode_channels(), 2);
    assert_eq!(restored.ptime_ms, 40);
}

#[test]
fn codec_snapshot_round_trips_the_amr_mode_set() {
    // The AMR counterpart: without `allowed_modes` a restored encoder could answer a peer's RFC
    // 4867 CMR with a mode that peer disallowed.
    let original = CodecSpec::new(96, "AMR-WB", 16_000, 1, 20)
        .with_encode_mode(Some(1))
        .with_allowed_modes(vec![0, 1]);
    let json = serde_json::to_string(&codec_snapshot(&original)).expect("serialize");
    let decoded: crate::ha::CodecSnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(restore_codec(&decoded), original);
}

#[test]
fn codec_snapshot_stays_compatible_with_a_pre_opus_standby() {
    // A snapshot written before these fields existed (and one for a plain G.711 leg) must still
    // restore: both new fields are `serde(default)` and are omitted when empty.
    let json = concat!(
        r#"{"payload_type":0,"encoding_name":"PCMU","clock_rate_hz":8000,"#,
        r#""channels":1,"ptime_ms":20}"#
    );
    let decoded: crate::ha::CodecSnapshot = serde_json::from_str(json).expect("deserialize");
    assert!(decoded.allowed_modes.is_empty());
    assert_eq!(decoded.opus, None);
    let restored = restore_codec(&decoded);
    assert_eq!(restored.encoding_name, "PCMU");
    assert!(restored.opus.is_none());
    // A plain G.711 snapshot does not grow either field.
    let plain = serde_json::to_string(&codec_snapshot(&CodecSpec::new(0, "PCMU", 8000, 1, 20)))
        .expect("serialize");
    assert!(!plain.contains("allowed_modes"), "{plain}");
    assert!(!plain.contains("opus"), "{plain}");
}

#[test]
fn transcode_codec_spec_advertises_only_what_the_factory_can_encode() {
    // The always-encodable set resolves, with its RFC 3551 static payload types.
    for (name, payload_type, clock) in [
        ("PCMU", 0u8, 8000u32),
        ("pcma", 8, 8000),
        ("G722", 9, 8000),
        ("GSM", 3, 8000),
    ] {
        let spec = transcode_codec_spec(name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(spec.payload_type, payload_type, "{name}");
        assert_eq!(spec.clock_rate_hz, clock, "{name}");
        assert_eq!(spec.channels, 1, "{name}");
    }
    // An unknown name never resolves.
    assert_eq!(transcode_codec_spec("EVS"), None);
    assert_eq!(transcode_codec_spec(""), None);

    // Opus resolves exactly when the factory can encode it, never otherwise — the table is gated
    // on a real `factory::encoder_for` probe, not on a hand-maintained availability list.
    let opus_probe = CodecSpec::new(
        OPUS_DYNAMIC_PAYLOAD_TYPE,
        "opus",
        siphon_rtp_codec::factory::OPUS_CLOCK_RATE_HZ,
        siphon_rtp_codec::factory::OPUS_RTPMAP_CHANNELS,
        20,
    );
    let encodable = factory::encoder_for(&opus_probe).is_ok();
    match transcode_codec_spec("OPUS") {
        None => assert!(
            !encodable,
            "Opus was withheld even though the factory can encode it"
        ),
        Some(spec) => {
            assert!(
                encodable,
                "Opus was advertised but the factory cannot encode it"
            );
            // RFC 7587: 48 kHz clock (§4.1) and rtpmap channel count 2 (§7), mono or not.
            assert_eq!(spec.clock_rate_hz, 48_000);
            assert_eq!(spec.channels, 2);
            assert_eq!(spec.ptime_ms, 20, "RFC 7587 §6.1 default ptime");
            assert_eq!(spec.payload_type, OPUS_DYNAMIC_PAYLOAD_TYPE);
        }
    }
}

#[test]
fn supported_codecs_advertises_opus_only_when_it_is_bidirectionally_transcodable() {
    let codecs = supported_codecs();
    // The always-available set is advertised unconditionally.
    for name in [
        "PCMU",
        "PCMA",
        "G722",
        "GSM",
        "CN",
        "L16",
        "telephone-event",
    ] {
        assert!(
            codecs.iter().any(|c| c == name),
            "{name} must be advertised"
        );
    }
    // Opus appears if and only if the factory can build both directions — advertising it while
    // only one worked would let a dispatcher route a call the engine then fails at setup.
    let advertised = codecs.iter().any(|c| c.eq_ignore_ascii_case("opus"));
    assert_eq!(
        advertised,
        opus_is_transcodable(),
        "the node_info codec list must track the factory, not a static list"
    );
    // Both halves of RFC 6716 are wired and Opus carries no build feature (royalty-free), so
    // this build is on the true side of that relationship: the dispatcher must see `opus`.
    assert!(
        opus_is_transcodable(),
        "Opus decode and encode are both wired, so the probe must say so"
    );
    assert!(advertised, "node_info must advertise opus");
    // And the transcode-target table resolves it too, so `codec-transcode-opus` can be forced.
    assert!(
        transcode_codec_spec("OPUS").is_some(),
        "a bidirectionally transcodable Opus must be a usable transcode target"
    );
}

#[test]
fn command_call_id_extracts_the_addressed_correlation_key() {
    let offer = Command::Offer {
        call_id: "call-42".into(),
        from_tag: "ft".into(),
        sdp: String::new(),
        profile: ProfileFlags::default(),
    };
    assert_eq!(command_call_id(&offer), Some("call-42"));

    let delete = Command::Delete {
        call_id: "call-42".into(),
        from_tag: "ft".into(),
        to_tag: None,
    };
    assert_eq!(command_call_id(&delete), Some("call-42"));

    // Conference verbs correlate on the conference id, not a call id.
    let leave = Command::ConferenceLeave {
        conference_id: "room-1".into(),
        from_tag: "ft".into(),
    };
    assert_eq!(command_call_id(&leave), Some("room-1"));

    // Census / health / cluster verbs address no specific call.
    assert_eq!(command_call_id(&Command::Ping), None);
    assert_eq!(command_call_id(&Command::List), None);
    assert_eq!(
        command_call_id(&Command::Restore {
            snapshot: String::new()
        }),
        None
    );
}

#[test]
fn chatty_commands_are_the_polled_read_only_verbs() {
    assert!(is_chatty_command(&Command::Ping));
    assert!(is_chatty_command(&Command::Statistics));
    assert!(is_chatty_command(&Command::NodeInfo));
    assert!(is_chatty_command(&Command::Query {
        call_id: "c".into(),
        from_tag: "ft".into(),
        to_tag: None,
    }));

    // The session-lifecycle verbs are NOT chatty — they log at INFO.
    let offer = Command::Offer {
        call_id: "c".into(),
        from_tag: "ft".into(),
        sdp: String::new(),
        profile: ProfileFlags::default(),
    };
    assert!(!is_chatty_command(&offer));
    let delete = Command::Delete {
        call_id: "c".into(),
        from_tag: "ft".into(),
        to_tag: None,
    };
    assert!(!is_chatty_command(&delete));
}

#[test]
fn qos_captures_emit_type35_reports_alongside_raw_rtcp() {
    // A compound Receiver Report (RFC 3550 §6.4.2) with one reception block: fraction_lost 13/256,
    // jitter 160 timestamp units. length = 7 words (32 bytes: 4 header + 4 reporter + 24 block).
    let mut rtcp = vec![0x81, 201, 0x00, 0x07];
    rtcp.extend_from_slice(&0xAAAA_0001u32.to_be_bytes()); // reporter ssrc
    rtcp.extend_from_slice(&0x1111_2222u32.to_be_bytes()); // reported-on ssrc
    rtcp.push(13); // fraction lost (13/256 ≈ 5.08 %)
    rtcp.extend_from_slice(&[0x00, 0x00, 0x02]); // cumulative lost
    rtcp.extend_from_slice(&0u32.to_be_bytes()); // extended highest seq
    rtcp.extend_from_slice(&160u32.to_be_bytes()); // jitter (160 @ 8 kHz = 20 ms)
    rtcp.extend_from_slice(&0u32.to_be_bytes()); // LSR
    rtcp.extend_from_slice(&0u32.to_be_bytes()); // DLSR

    let observed = ObservedRtcp {
        endpoint: EndpointId(1),
        source: "198.51.100.1:6000".parse().expect("src"),
        destination: "203.0.113.1:6002".parse().expect("dst"),
        payload: bytes::Bytes::from(rtcp.clone()),
    };

    // The raw RTCP passthrough is unchanged (protocol_type RTCP, bytes verbatim).
    let raw = rtcp_capture(&observed, "call-42@host".into(), 7, 100, 0);
    assert_eq!(raw.protocol_type, protocol_type::RTCP);
    assert_eq!(raw.payload, rtcp);

    // ...and one QoS/MOS report per reception block (protocol_type REPORT_JSON = HEP3 type 35).
    let captures = qos_captures(
        &observed,
        "call-42@host",
        7,
        100,
        0,
        siphon_rtp_hep::mos::Codec::G711,
        8000,
    );
    assert_eq!(captures.len(), 1, "one QoS report per reception block");
    let capture = &captures[0];
    assert_eq!(capture.protocol_type, protocol_type::REPORT_JSON);
    assert_eq!(capture.correlation_id.as_deref(), Some("call-42@host"));
    let json = std::str::from_utf8(&capture.payload).expect("utf8 payload");
    // Reported-on SSRC 0x1111_2222 = 286335522.
    assert!(json.contains(r#""ssrc":286335522"#), "{json}");
    assert!(json.contains(r#""codec":"G711""#), "{json}");
    assert!(
        json.contains(r#""loss_percent":5.08"#),
        "13/256 → 5.08 %: {json}"
    );
    assert!(
        json.contains(r#""jitter_ms":20.00"#),
        "160 @ 8 kHz → 20 ms: {json}"
    );
    assert!(json.contains(r#""mos":"#), "{json}");

    // ...and the SAME per-block loss/jitter/MOS natively on the control channel, keyed by
    // `call_id` (not `conference_id`), for the 2-party plain-relay call.
    let events = qos_quality_events(
        &observed,
        "call-42@host",
        "caller",
        siphon_rtp_hep::mos::Codec::G711,
        8000,
    );
    assert_eq!(events.len(), 1, "one quality event per reception block");
    match &events[0] {
        Event::CallQuality {
            conference_id,
            call_id,
            from_tag,
            jitter_ms,
            loss_percent,
            mos,
        } => {
            assert!(
                conference_id.is_none(),
                "a 2-party relay carries no conference_id"
            );
            assert_eq!(call_id.as_deref(), Some("call-42@host"));
            assert_eq!(from_tag, "caller");
            // 13/256 → 5.078125 %, 160 @ 8 kHz → 20 ms — the exact figures the HEP report carries.
            assert!(
                (*loss_percent - (13.0 / 256.0 * 100.0)).abs() < 1e-9,
                "13/256 → 5.08 %, got {loss_percent}"
            );
            assert!(
                (*jitter_ms - 20.0).abs() < 1e-9,
                "160 @ 8 kHz → 20 ms, got {jitter_ms}"
            );
            // The MOS is the G.107 estimate for that loss/jitter — a good-but-not-perfect call.
            assert!(*mos > 1.0 && *mos < 4.5, "plausible MOS, got {mos}");
        }
        other => panic!("expected CallQuality, got {other:?}"),
    }
}

#[test]
fn qos_quality_events_ignores_rtcp_without_reception_blocks() {
    // A minimal RR with reception-count 0 (no blocks) yields no quality event — nothing to report.
    let rtcp = vec![0x80, 201, 0x00, 0x01, 0xAA, 0xAA, 0x00, 0x01];
    let observed = ObservedRtcp {
        endpoint: EndpointId(1),
        source: "198.51.100.1:6000".parse().expect("src"),
        destination: "203.0.113.1:6002".parse().expect("dst"),
        payload: bytes::Bytes::from(rtcp),
    };
    let events = qos_quality_events(
        &observed,
        "call-x",
        "caller",
        siphon_rtp_hep::mos::Codec::G711,
        8000,
    );
    assert!(events.is_empty(), "no reception block ⇒ no quality event");
}

/// A two-port SDP: RTP at `addr`, RTCP at `addr`+1 (default), optional `a=rtcp-mux`. The
/// addrtype (RFC 4566 §5.7) follows `rtp`'s family, so this builds an `IN IP6` offer for a v6
/// socket and `IN IP4` for a v4 one.
fn sdp_for(rtp: SocketAddr, mux: bool) -> String {
    let mux_line = if mux { "a=rtcp-mux\r\n" } else { "" };
    let addrtype = if rtp.is_ipv6() { "IP6" } else { "IP4" };
    format!(
        "v=0\r\no=- 1 1 IN {addrtype} {ip}\r\ns=-\r\nc=IN {addrtype} {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000\r\n{mux_line}",
        ip = rtp.ip(),
        port = rtp.port()
    )
}

/// A test "phone" bound to IPv6 loopback (`::1`) — the v6 counterpart of [`phone`].
async fn phone_v6() -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0))
        .await
        .expect("bind v6");
    let addr = socket.local_addr().expect("v6 addr");
    (socket, addr)
}

fn ok_sdp_text(result: &CmdResult) -> String {
    match result {
        CmdResult::Ok { sdp: Some(sdp), .. } => sdp.clone(),
        other => panic!("expected Ok with sdp, got {other:?}"),
    }
}

/// A [`Datapath`] test double: it wraps the real loopback backend (so offer/answer sets up genuine
/// relay flows) but overrides [`Datapath::learned_source`] from an injected per-endpoint map — the
/// split userspace/kernel behaviour the XDP backend has and that `refresh_latched_destinations`
/// consumes. It also records every `install_flow` call so a test can assert exactly which flow the
/// sweep reprogrammed.
// The `learned` map and `installs` log are behind `Arc` so every clone (the engine holds one)
// shares one view — a deep-cloned `DashMap` would hide a test's injected latch from the engine.
#[derive(Clone)]
struct LatchLearningDatapath {
    inner: UdpLoopbackDatapath,
    /// Injected per-endpoint learned sources — what `learned_source` returns (the kernel latch).
    learned: Arc<DashMap<EndpointId, SocketAddr>>,
    /// An ordered log of every `(endpoint, action)` installed, for assertions.
    installs: Arc<Mutex<Vec<(EndpointId, FlowAction)>>>,
}

impl LatchLearningDatapath {
    fn new() -> Self {
        Self {
            inner: UdpLoopbackDatapath::new(),
            learned: Arc::new(DashMap::new()),
            installs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record that `endpoint`'s in-kernel ingress latch has learned `source`.
    fn set_learned(&self, endpoint: EndpointId, source: SocketAddr) {
        self.learned.insert(endpoint, source);
    }

    /// Drain the captured install log, so a test measures only the installs since the last drain.
    fn take_installs(&self) -> Vec<(EndpointId, FlowAction)> {
        std::mem::take(&mut self.installs.lock().expect("install log lock"))
    }
}

impl Datapath for LatchLearningDatapath {
    fn alloc_endpoint(
        &self,
    ) -> impl std::future::Future<Output = Result<Endpoint, siphon_rtp_datapath::DatapathError>> + Send
    {
        self.inner.alloc_endpoint()
    }

    fn alloc_endpoint_for(
        &self,
        family: AddressFamily,
    ) -> impl std::future::Future<Output = Result<Endpoint, siphon_rtp_datapath::DatapathError>> + Send
    {
        self.inner.alloc_endpoint_for(family)
    }

    fn alloc_endpoint_on_port(
        &self,
        family: AddressFamily,
        port: u16,
    ) -> impl std::future::Future<Output = Result<Endpoint, siphon_rtp_datapath::DatapathError>> + Send
    {
        self.inner.alloc_endpoint_on_port(family, port)
    }

    fn install_flow(
        &self,
        endpoint: EndpointId,
        action: FlowAction,
    ) -> Result<(), siphon_rtp_datapath::DatapathError> {
        self.installs
            .lock()
            .expect("install log lock")
            .push((endpoint, action));
        self.inner.install_flow(endpoint, action)
    }

    fn remove_flow(&self, endpoint: EndpointId) {
        self.inner.remove_flow(endpoint);
    }

    fn remove_endpoint(
        &self,
        endpoint: EndpointId,
    ) -> impl std::future::Future<Output = ()> + Send {
        self.inner.remove_endpoint(endpoint)
    }

    fn send(
        &self,
        endpoint: EndpointId,
        dst: SocketAddr,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<usize, siphon_rtp_datapath::DatapathError>> + Send
    {
        self.inner.send(endpoint, dst, data)
    }

    fn stats(&self, endpoint: EndpointId) -> Option<siphon_rtp_datapath::EndpointStats> {
        self.inner.stats(endpoint)
    }

    fn now_ticks(&self) -> u64 {
        self.inner.now_ticks()
    }

    fn advance_clock(&self, ticks: u64) {
        self.inner.advance_clock(ticks);
    }

    fn now_micros(&self) -> u64 {
        self.inner.now_micros()
    }

    fn last_activity(&self, endpoint: EndpointId) -> Option<u64> {
        self.inner.last_activity(endpoint)
    }

    fn note_activity(&self, endpoint: EndpointId) {
        self.inner.note_activity(endpoint);
    }

    // The override under test: expose the injected kernel-learned source.
    fn learned_source(&self, endpoint: EndpointId) -> Option<SocketAddr> {
        self.learned.get(&endpoint).map(|entry| *entry.value())
    }

    fn set_ice(&self, endpoint: EndpointId, config: Option<IceConfig>) {
        self.inner.set_ice(endpoint, config);
    }

    fn rx(&self) -> flume::Receiver<siphon_rtp_datapath::RxPacket> {
        self.inner.rx()
    }

    fn observe_rtcp(&self) -> flume::Receiver<ObservedRtcp> {
        self.inner.observe_rtcp()
    }
}

/// The `out_dst` of the `Forward` flow installed on `endpoint`, read out of the call's `relay_flows`.
fn relay_out_dst<D: Datapath>(
    engine: &Engine<D>,
    call_id: &str,
    endpoint: EndpointId,
) -> Option<SocketAddr> {
    let call = engine.calls.get(call_id).expect("call present");
    call.relay_flows
        .iter()
        .find_map(|(installed, action)| match action {
            FlowAction::Forward(rule) if *installed == endpoint => Some(rule.out_dst),
            _ => None,
        })
        .flatten()
}

#[tokio::test]
async fn refresh_latched_destinations_reprograms_the_sibling_out_dst_from_the_kernel_latch() {
    // A NATed peer whose real source differs from the signalled address: the kernel latches it on
    // the far leg's ingress, and the engine sweep must propagate that learned source into the
    // *near→far* flow's `out_dst` (docs/security-and-nat.md §4 layer 3, RFC 3550 §8).
    let datapath = LatchLearningDatapath::new();
    let engine = Engine::new(datapath.clone());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    // A plain PCMU relay (no profile flags) → Passthrough with in-kernel `Forward` flows.
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "nat-call".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "nat-call".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;

    let (near_rtp, far_rtp) = {
        let call = engine.calls.get("nat-call").expect("call present");
        (call.near.rtp.id, call.far_leg().rtp.id)
    };
    // Before the sweep: near→far forwards to B's signalled address; far→near to A's.
    assert_eq!(
        relay_out_dst(&engine, "nat-call", near_rtp),
        Some(addr_b),
        "near→far initially forwards to B's signalled address"
    );
    let far_out_dst_before = relay_out_dst(&engine, "nat-call", far_rtp);

    // The kernel learned B's REAL post-NAT source on the far leg's ingress (a symmetric-NAT rebind),
    // differing from the signalled address. 203.0.113.0/24 is the RFC 5737 documentation range.
    let learned_b: SocketAddr = "203.0.113.7:40004".parse().expect("addr");
    assert_ne!(
        learned_b, addr_b,
        "the learned source must differ to exercise the propagation"
    );
    datapath.set_learned(far_rtp, learned_b);
    // The near leg has NOT learned anything: the far→near flow must stay untouched.

    let _ = datapath.take_installs(); // Drop the offer/answer installs; measure only the sweep.
    engine.refresh_latched_destinations().await;

    // (a) Exactly one flow was reinstalled — the near→far flow, now aimed at B's learned source.
    let installs = datapath.take_installs();
    assert_eq!(
        installs.len(),
        1,
        "only the near→far flow is reprogrammed, got {installs:?}"
    );
    let (reinstalled_on, reinstalled_action) = installs[0];
    assert_eq!(
        reinstalled_on, near_rtp,
        "reprogrammed the near endpoint (forwards toward B)"
    );
    match reinstalled_action {
        FlowAction::Forward(rule) => {
            assert_eq!(
                rule.out_dst,
                Some(learned_b),
                "out_dst set to the kernel-learned source"
            );
            assert_eq!(rule.out_endpoint, far_rtp, "still the near→far direction");
        }
        other => panic!("expected a Forward action, got {other:?}"),
    }

    // (b) relay_flows now carries the updated action (so block/unblock restores the learned dst)...
    assert_eq!(
        relay_out_dst(&engine, "nat-call", near_rtp),
        Some(learned_b),
        "relay_flows holds the learned destination after the sweep"
    );
    // ...and the far→near flow (near never learned) is untouched.
    assert_eq!(
        relay_out_dst(&engine, "nat-call", far_rtp),
        far_out_dst_before,
        "far→near untouched: near never learned a source"
    );

    // Idempotence: a second sweep with the same learned source reinstalls nothing new.
    engine.refresh_latched_destinations().await;
    assert!(
        datapath.take_installs().is_empty(),
        "idempotent: no reinstall once out_dst already equals the learned source"
    );
}

#[tokio::test]
async fn refresh_latched_destinations_is_a_noop_on_the_loopback_backend() {
    // The loopback backend's `learned_source` defaults to `None` (it resolves the latch inline when
    // forwarding, owning both legs), so the sweep reprograms nothing — relay_flows are unchanged.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "loop-call".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "loop-call".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;

    let before = engine
        .calls
        .get("loop-call")
        .expect("call present")
        .relay_flows
        .clone();
    assert!(!before.is_empty(), "a plain relay installs Forward flows");
    engine.refresh_latched_destinations().await;
    let after = engine
        .calls
        .get("loop-call")
        .expect("call present")
        .relay_flows
        .clone();
    assert_eq!(
        before, after,
        "loopback learned_source is None → the sweep reprograms nothing"
    );
}

#[tokio::test]
async fn offer_codec_strip_removes_the_codec_from_the_offered_sdp() {
    // rtpengine `codec-strip-PCMA`: the SDP the engine offers the far side drops PCMA (static
    // PT 8, resolved via the RFC 3551 table — `sdp_for` carries no rtpmap for it).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let profile = ProfileFlags {
        flags: vec!["codec-strip-PCMA".into()],
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "strip".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr, true),
                profile,
            },
        )
        .await;
    let sdp = ok_sdp_text(&offer);
    let m_line = sdp
        .lines()
        .find(|l| l.starts_with("m=audio"))
        .expect("m=audio line");
    assert!(m_line.ends_with(" 0"), "only PCMU (PT 0) remains: {m_line}");
    assert!(!m_line.contains(" 8"), "PCMA (PT 8) stripped: {m_line}");
}

#[tokio::test]
async fn offer_codec_transcode_adds_the_codec_to_the_offered_sdp() {
    // rtpengine `codec-transcode-G722`: the engine adds G722 (PT 9 + rtpmap) to the offered SDP.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let profile = ProfileFlags {
        flags: vec!["codec-transcode-G722".into()],
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "xcode".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr, true),
                profile,
            },
        )
        .await;
    let sdp = ok_sdp_text(&offer);
    let m_line = sdp
        .lines()
        .find(|l| l.starts_with("m=audio"))
        .expect("m=audio line");
    assert!(m_line.ends_with(" 9"), "G722 (PT 9) appended: {m_line}");
    assert!(
        sdp.contains("a=rtpmap:9 G722/8000"),
        "G722 rtpmap added: {sdp}"
    );
}

#[tokio::test]
async fn answer_ptime_override_advertises_the_re_framed_egress_ptime() {
    // A offers PCMU; B answers PCMA → the engine transcodes (Media pipeline). A `ptime=40` override
    // on the answer must surface as `a=ptime:40` in the answer SDP presented to A (the packetization
    // A will receive), never the far side's 20 ms — end-to-end from the control flag to the wire.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ptime-call".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    // B answers PCMA (PT 8) as its primary → codec mismatch → transcode, with a=ptime:20.
    let b_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=rtcp-mux\r\na=ptime:20\r\n",
        ip = addr_b.ip(),
        port = addr_b.port()
    );
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ptime-call".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: b_sdp,
                profile: ProfileFlags {
                    flags: vec!["ptime=40".into()],
                    ..Default::default()
                },
            },
        )
        .await;
    let sdp = ok_sdp_text(&answer);
    assert!(
        sdp.contains("a=ptime:40"),
        "answer to A advertises the 40 ms override: {sdp}"
    );
    assert!(
        !sdp.contains("a=ptime:20"),
        "B's 20 ms ptime is not leaked to A: {sdp}"
    );
    let parsed = sdp::parse(&sdp).expect("reparse");
    assert_eq!(
        parsed.ptime_ms, 40,
        "the answer reparses to the overridden ptime"
    );
    assert_eq!(
        parsed.primary_codec().expect("codec").encoding_name,
        "PCMU",
        "A is presented its own codec at the overridden ptime"
    );
}

#[test]
fn parse_codec_flags_maps_rtpengine_operations() {
    // Each rtpengine codec op (docs/ng_control_protocol.md) resolves onto the CodecPolicy.
    let policy = parse_codec_flags(&[
        "codec-mask-PCMA".into(),
        "codec-except-PCMU".into(),
        "codec-accept-GSM".into(),
        "codec-offer-G722".into(),
        "codec-strip-all".into(),
        "codec-transcode-PCMA".into(),
    ]);
    assert!(policy.remove_all, "strip-all → remove_all");
    assert_eq!(
        policy.remove,
        vec!["PCMA".to_string()],
        "mask feeds the remove set"
    );
    assert!(
        policy.keep.contains(&"PCMU".to_string()),
        "except → keep-list"
    );
    assert!(
        policy.keep.contains(&"GSM".to_string()),
        "accept → keep-list"
    );
    assert_eq!(
        policy.order,
        vec!["G722".to_string()],
        "offer → far-offer order"
    );
    assert_eq!(policy.add.len(), 1, "transcode → one added codec");
    assert_eq!(policy.add[0].encoding_name, "PCMA");
    // Lowercase names are matched case-insensitively (stored uppercased).
    let lower = parse_codec_flags(&["codec-mask-pcma".into()]);
    assert_eq!(lower.remove, vec!["PCMA".to_string()]);
}

#[test]
fn parse_ptime_override_reads_the_flag_and_clamps_it() {
    assert_eq!(parse_ptime_override(&["ptime=40".into()]), Some(40));
    assert_eq!(parse_ptime_override(&["ptime=10".into()]), Some(10));
    assert_eq!(parse_ptime_override(&[]), None, "absent → no override");
    assert_eq!(
        parse_ptime_override(&["symmetric".into(), "ptime=30".into()]),
        Some(30),
        "found among other flags"
    );
    assert_eq!(
        parse_ptime_override(&["ptime=500".into()]),
        Some(MAX_PTIME_OVERRIDE_MS),
        "an absurd ptime is clamped to the ceiling"
    );
    // The control flag and the negotiated `a=ptime` must answer the same request the same way.
    // These were two different ceilings (40 vs 120), so `a=ptime:60` was honoured while
    // `ptime=60` was silently clamped to 40 — the same call, two answers, one of them invisible.
    assert_eq!(
        MAX_PTIME_OVERRIDE_MS, OPUS_MAX_PTIME_MS,
        "the control-flag ceiling must equal the negotiated one, or the two paths disagree"
    );
    for requested in [60u8, 80, 100, 120] {
        assert_eq!(
            parse_ptime_override(&[format!("ptime={requested}")]),
            Some(requested),
            "a long ptime the negotiated path accepts must not be clamped on the control flag"
        );
    }
    assert_eq!(
        parse_ptime_override(&["ptime=0".into()]),
        None,
        "0 ms rejected"
    );
    assert_eq!(
        parse_ptime_override(&["ptime=".into()]),
        None,
        "empty value rejected"
    );
    assert_eq!(
        parse_ptime_override(&["ptime=abc".into()]),
        None,
        "non-numeric rejected"
    );
}

#[test]
fn with_ptime_override_reframes_only_when_present() {
    let g711 = CodecSpec::new(0, "PCMU", 8000, 1, 20);
    assert_eq!(
        with_ptime_override(&g711, Some(40)).ptime_ms,
        40,
        "override applied"
    );
    assert_eq!(
        with_ptime_override(&g711, None).ptime_ms,
        20,
        "no override → negotiated ptime stands"
    );
    // Only ptime changes; the rest of the spec is untouched.
    let overridden = with_ptime_override(&g711, Some(30));
    assert_eq!(overridden.encoding_name, "PCMU");
    assert_eq!(overridden.clock_rate_hz, 8000);
    assert_eq!(overridden.payload_type, 0);
}

#[tokio::test]
async fn offer_codec_mask_hides_the_codec_from_the_far_side() {
    // rtpengine `codec-mask-PCMA` (asymmetric hide): PCMA is dropped from the offer to B (same
    // far-offer edit as strip), while the near leg keeps it usable for transcoding.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let profile = ProfileFlags {
        flags: vec!["codec-mask-PCMA".into()],
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "mask".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr, true),
                profile,
            },
        )
        .await;
    let sdp = ok_sdp_text(&offer);
    let m_line = sdp
        .lines()
        .find(|l| l.starts_with("m=audio"))
        .expect("m=audio line");
    assert!(
        m_line.ends_with(" 0"),
        "PCMA hidden from B, PCMU offered: {m_line}"
    );
    assert!(!m_line.contains(" 8"), "PCMA (PT 8) masked: {m_line}");
}

#[tokio::test]
async fn offer_codec_offer_reorders_the_far_offer() {
    // rtpengine `codec-offer`: a whitelist that sets the offered order — PCMA before PCMU here.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let profile = ProfileFlags {
        flags: vec!["codec-offer-PCMA".into(), "codec-offer-PCMU".into()],
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "reorder".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr, true),
                profile,
            },
        )
        .await;
    let sdp = ok_sdp_text(&offer);
    let m_line = sdp
        .lines()
        .find(|l| l.starts_with("m=audio"))
        .expect("m=audio line");
    assert!(
        m_line.ends_with("RTP/AVP 8 0"),
        "PCMA (8) offered before PCMU (0): {m_line}"
    );
}

#[tokio::test]
async fn offer_replace_origin_rewrites_the_o_line_to_the_engine_address() {
    // rtpengine `replace: [origin]`: the o= unicast-address is rewritten to the engine's (topology
    // hiding). The offer's o= carries a distinct 10.0.0.7 so the loopback engine address differs.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let offer_sdp = format!(
        "v=0\r\no=alice 1 1 IN IP4 10.0.0.7\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
        ip = addr.ip(),
        port = addr.port()
    );
    let profile = ProfileFlags {
        replace: vec!["origin".into()],
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ro".into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile,
            },
        )
        .await;
    let sdp = ok_sdp_text(&offer);
    let o_line = sdp.lines().find(|l| l.starts_with("o=")).expect("o= line");
    assert!(
        !o_line.contains("10.0.0.7"),
        "the caller's origin IP is hidden: {o_line}"
    );
    assert!(
        o_line.contains(&addr.ip().to_string()),
        "o= now carries the engine's advertised (loopback) address: {o_line}"
    );
}

#[test]
fn far_address_family_parses_the_flag() {
    let with = |value: &str| ProfileFlags {
        address_family: Some(value.into()),
        ..Default::default()
    };
    assert_eq!(far_address_family(&with("IP6")), Some(AddressFamily::V6));
    assert_eq!(far_address_family(&with("ip4")), Some(AddressFamily::V4));
    assert_eq!(far_address_family(&with(" IP6 ")), Some(AddressFamily::V6));
    assert_eq!(
        far_address_family(&with("IP9")),
        None,
        "unknown family ignored"
    );
    assert_eq!(far_address_family(&ProfileFlags::default()), None);
}

#[test]
fn resolve_toward_a_honours_from_tag_and_to_tag() {
    // A 2-leg call (to-tag "b"): the offerer (from_tag "a") plays toward leg A by default.
    assert!(resolve_toward_a("a", Some("b"), None));
    // from_tag naming the to-tag ⇒ leg B — the historical selection stays working.
    assert!(!resolve_toward_a("b", Some("b"), None));
    // to_tag naming the call's to-tag ⇒ leg B, even when from_tag is the offerer (B18: honoured).
    assert!(!resolve_toward_a("a", Some("b"), Some("b")));
    // A to_tag that does not match the call's to-tag does not select leg B.
    assert!(resolve_toward_a("a", Some("b"), Some("nomatch")));
    // An unanswered call (no to-tag) always resolves to leg A.
    assert!(resolve_toward_a("a", None, Some("b")));
}

#[test]
fn apply_replace_directives_applies_origin_and_reports_the_rest() {
    let ip: std::net::IpAddr = "203.0.113.9".parse().expect("ip");
    let sdp = "v=0\r\no=alice 1 1 IN IP4 10.0.0.7\r\ns=-\r\nc=IN IP4 10.0.0.7\r\nt=0 0\r\n";
    let o_line = |text: &str| {
        text.lines()
            .find(|line| line.starts_with("o="))
            .expect("o= line")
            .to_string()
    };

    // `origin` rewrites only the o= line's unicast address; nothing is reported unsupported.
    let (rewritten, unsupported) = apply_replace_directives(sdp, &["origin".into()], ip);
    assert!(o_line(&rewritten).contains("203.0.113.9"));
    assert!(!o_line(&rewritten).contains("10.0.0.7"));
    assert!(unsupported.is_empty());

    // An unimplemented token is reported (not silently swallowed); the SDP is untouched.
    let (unchanged, unsupported) =
        apply_replace_directives(sdp, &["session-connection".into()], ip);
    assert_eq!(unchanged, sdp);
    assert_eq!(unsupported, vec!["session-connection".to_string()]);

    // Mixed: `origin` still applies (case-insensitive) and every other token is reported back.
    let (mixed, unsupported) = apply_replace_directives(
        sdp,
        &["Origin".into(), "zero-address".into(), "SDES".into()],
        ip,
    );
    assert!(o_line(&mixed).contains("203.0.113.9"));
    assert_eq!(
        unsupported,
        vec!["zero-address".to_string(), "SDES".to_string()]
    );
}

#[tokio::test]
async fn offer_address_family_ip4_puts_the_far_leg_on_ipv4_for_a_v6_offer() {
    // IPv4↔IPv6 interworking: a v6 (VoLTE) offer with `address family = IP4` (PSTN core) allocates
    // the far leg on IPv4, advertised to B as `c=IN IP4`, while the near leg stays v6.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer_sdp = "v=0\r\no=- 1 1 IN IP6 ::1\r\ns=-\r\nc=IN IP6 ::1\r\nt=0 0\r\n\
                         m=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n";
    let profile = ProfileFlags {
        address_family: Some("IP4".into()),
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "xfam".into(),
                from_tag: "a".into(),
                sdp: offer_sdp.into(),
                profile,
            },
        )
        .await;
    let sdp = ok_sdp_text(&offer);
    let c_line = sdp
        .lines()
        .find(|l| l.starts_with("c="))
        .expect("c= line in the far-facing offer");
    assert!(
        c_line.contains("IN IP4 127.0.0.1"),
        "the far (PSTN) leg is advertised on IPv4: {c_line}"
    );
}

async fn recv(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; 2048];
    let (len, from) = timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
        .await
        .expect("no timeout")
        .expect("recv");
    (buffer[..len].to_vec(), from)
}

/// A `RTP/SAVP` answer SDP at `addr` carrying `crypto` (rtcp-mux, so it is a single port).
fn savp_answer_sdp(addr: SocketAddr, crypto: &CryptoAttribute) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 0 8\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na={crypto_line}\r\n",
        ip = addr.ip(),
        port = addr.port(),
        crypto_line = crypto.to_attribute_value(),
    )
}

/// A `RTP/SAVP` answer SDP advertising a single static codec (`payload_type`/`name`) at `addr`
/// with `crypto` (rtcp-mux). A different codec than the plaintext near leg makes the call a secure
/// *transcode* (`PipelineKind::SrtpMedia`), not a plain SRTP bridge.
fn savp_answer_codec(
    addr: SocketAddr,
    payload_type: u8,
    name: &str,
    crypto: &CryptoAttribute,
) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP {pt}\r\na=rtpmap:{pt} {name}/8000\r\na=rtcp-mux\r\na={crypto_line}\r\n",
        ip = addr.ip(),
        port = addr.port(),
        pt = payload_type,
        crypto_line = crypto.to_attribute_value(),
    )
}

fn rtp_packet(seq: u16, ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(b"amr-wb-frame----");
    packet
}

#[tokio::test]
async fn ping_pongs() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    assert_eq!(engine.handle(CLIENT, Command::Ping).await, CmdResult::Pong);
}

#[tokio::test]
async fn load_reports_configured_capacity_and_gauges() {
    let cluster = std::sync::Arc::new(crate::cluster::ClusterState::new(
        "rtp-test-1".to_string(),
        4000,
        vec!["203.0.113.10".to_string()],
    ));
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_cluster(cluster);
    let CmdResult::Load { load } = engine.handle(CLIENT, Command::Load).await else {
        panic!("expected load result");
    };
    assert_eq!(load.node_id, "rtp-test-1");
    assert_eq!(load.max_sessions, 4000);
    assert_eq!(load.sessions, 0, "no live calls yet");
    assert_eq!(load.load_permille, 0, "empty node is 0 load");
    assert_eq!(load.transcode_sessions, 0);
    assert!(!load.draining);
}

#[tokio::test]
async fn node_info_reports_identity_and_capabilities() {
    let cluster = std::sync::Arc::new(crate::cluster::ClusterState::new(
        "rtp-test-2".to_string(),
        1000,
        vec!["203.0.113.11".to_string()],
    ));
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_cluster(cluster);
    let CmdResult::NodeInfo { node } = engine.handle(CLIENT, Command::NodeInfo).await else {
        panic!("expected node_info result");
    };
    assert_eq!(node.node_id, "rtp-test-2");
    assert_eq!(node.max_sessions, 1000);
    assert_eq!(node.media_addresses, vec!["203.0.113.11".to_string()]);
    assert!(
        node.codecs.iter().any(|codec| codec == "PCMU"),
        "advertises G.711"
    );
    assert!(node.features.iter().any(|feature| feature == "relay"));
    assert_eq!(node.version, env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn drain_refuses_new_offers_but_keeps_serving_control() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let offer = || Command::Offer {
        call_id: "drain-call".to_string(),
        from_tag: "ft".to_string(),
        sdp: sdp_for(addr, true),
        profile: ProfileFlags::default(),
    };

    // Enter drain mode: a new offer is refused with a "draining" reason...
    assert_eq!(engine.handle(CLIENT, Command::Drain).await, ok_empty());
    match engine.handle(CLIENT, offer()).await {
        CmdResult::Error { reason } => assert!(reason.contains("draining"), "{reason}"),
        other => panic!("expected drain rejection, got {other:?}"),
    }
    // ...but liveness and the cluster/census verbs still answer, and `load` shows draining.
    assert_eq!(engine.handle(CLIENT, Command::Ping).await, CmdResult::Pong);
    let CmdResult::Load { load } = engine.handle(CLIENT, Command::Load).await else {
        panic!("load");
    };
    assert!(load.draining, "load snapshot reflects drain state");

    // Undrain re-opens admission: the same offer now succeeds.
    assert_eq!(engine.handle(CLIENT, Command::Undrain).await, ok_empty());
    assert!(
        matches!(engine.handle(CLIENT, offer()).await, CmdResult::Ok { .. }),
        "offer admitted again after undrain"
    );
}

#[tokio::test]
async fn checkpoint_captures_a_plain_relay_snapshot() {
    use crate::ha::{CallSnapshot, EndpointRole, PipelineSnapshot};

    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    // A plain PCMU relay: offer + answer, no profile flags → Passthrough.
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ckpt-call".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let far_local = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ckpt-call".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;

    // Checkpoint returns an opaque blob that deserializes to the negotiated state.
    let CmdResult::Checkpoint { snapshot } = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "ckpt-call".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("expected a checkpoint result");
    };
    let snapshot = CallSnapshot::from_json(&snapshot).expect("valid snapshot blob");
    assert_eq!(snapshot.call_id, "ckpt-call");
    assert_eq!(snapshot.from_tag, "tag-a");
    assert_eq!(snapshot.to_tag.as_deref(), Some("tag-b"));
    assert_eq!(snapshot.pipeline, PipelineSnapshot::Passthrough);
    // rtcp-mux ⇒ no companion RTCP endpoint; the far leg advertises the engine port A dials.
    assert!(
        snapshot.near.rtcp_local.is_none(),
        "rtcp-mux: no near RTCP port"
    );
    assert_eq!(
        snapshot.far.rtp_local, far_local,
        "far leg local port is captured"
    );
    assert_eq!(
        snapshot.near.remote_rtp,
        Some(addr_a),
        "A's address captured"
    );
    assert_eq!(
        snapshot.far.remote_rtp,
        Some(addr_b),
        "B's address captured"
    );
    // A plain relay installs Forward rules on both RTP endpoints (mux ⇒ two, not four).
    assert!(
        snapshot
            .flows
            .iter()
            .any(|flow| flow.installed_on == EndpointRole::NearRtp
                && flow.out == EndpointRole::FarRtp),
        "near→far forward rule captured"
    );
    assert!(
        snapshot.secure.is_none(),
        "a plain relay has no secure state"
    );
}

#[tokio::test]
async fn checkpoint_is_ownership_gated() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "owned".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    // A different client cannot checkpoint (nor even learn the call exists) — A3, docs §5.
    let other = ClientId(999);
    assert!(matches!(
        engine
            .handle(
                other,
                Command::Checkpoint {
                    call_id: "owned".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await,
        CmdResult::Error { .. }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_resumes_a_plain_relay_on_a_standby_at_the_same_ports() {
    // Warm-standby HA end to end: a plain relay is set up on "node A", checkpointed, torn down
    // (A dies, freeing its ports), then restored on a fresh "node B" that re-binds the *same*
    // media ports (as a floating-IP standby would) — and media relays through B with no
    // re-negotiation. Both nodes use the same deterministic port range on loopback.
    let (min, max) = (46_000u16, 46_040u16);
    let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let engine_a = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    // A plain PCMU relay (offer + answer, rtcp-mux, no profile) on node A.
    let offer = engine_a
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ha-relay".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    // The engine address B will send to (advertised in the offer sent onward to B).
    let engine_far = sdp::parse(&ok_sdp_text(&offer)).expect("offer").remote_rtp;
    let answer = engine_a
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ha-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    // The engine address A sends to (advertised back to A in the answer).
    let engine_near = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer")
        .remote_rtp;

    // Checkpoint the live call, then delete it on A and drop A — freeing the media ports.
    let CmdResult::Checkpoint { snapshot } = engine_a
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "ha-relay".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("expected a checkpoint result");
    };
    engine_a
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "ha-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(engine_a);

    // Node B (same port range + bind IP) restores from the blob, re-binding the same ports.
    let engine_b = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    assert!(
        matches!(
            engine_b.handle(CLIENT, Command::Restore { snapshot }).await,
            CmdResult::Ok { .. }
        ),
        "restore succeeds on the standby"
    );

    // Media now relays through B at the unchanged engine ports — no re-INVITE needed.
    // A → engine_near → B receives at addr_b.
    let a_to_b = g711_rtp(0, 1, 0x0A0A_0A0A, 0xA1);
    phone_a.send_to(&a_to_b, engine_near).await.expect("a send");
    let (got_b, _) = recv(&phone_b).await;
    assert_eq!(got_b, a_to_b, "A→B relays through the restored node");

    // B → engine_far → A receives at addr_a.
    let b_to_a = g711_rtp(0, 2, 0x0B0B_0B0B, 0xB2);
    phone_b.send_to(&b_to_a, engine_far).await.expect("b send");
    let (got_a, _) = recv(&phone_a).await;
    assert_eq!(got_a, b_to_a, "B→A relays through the restored node");
}

#[tokio::test]
async fn restore_rejects_a_stale_or_duplicate_call() {
    // A blob for a call that is already live is refused (no clobbering a live call).
    let engine = Engine::new(UdpLoopbackDatapath::with_port_range(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        47_000,
        47_020,
    ));
    let (_phone_a, addr_a) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dup".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dup".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let CmdResult::Checkpoint { snapshot } = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "dup".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("checkpoint");
    };
    // The call is still live → restoring the same id is rejected.
    assert!(matches!(
        engine.handle(CLIENT, Command::Restore { snapshot }).await,
        CmdResult::Error { .. }
    ));
    // A malformed blob is a clean error, never a panic.
    assert!(matches!(
        engine
            .handle(
                CLIENT,
                Command::Restore {
                    snapshot: "{not valid".into(),
                },
            )
            .await,
        CmdResult::Error { .. }
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_resumes_a_secure_srtp_bridge_on_a_standby() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_srtp::SrtpContext;

    // Secure warm-standby HA: an AVP↔SAVP bridge is set up on node A, checkpointed (capturing the
    // peer's key + the leg rollover + the bridge flows), torn down, then restored on node B which
    // re-binds the same ports and rebuilds the SRTP bridge — and secure media flows through B.
    let (min, max) = (48_000u16, 48_060u16);
    let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let engine_a = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    tokio::spawn(run_redirect_dispatcher(
        engine_a.datapath().rx(),
        engine_a.bridge(),
        engine_a.media(),
        engine_a.ws(),
        engine_a.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await; // plain (AVP) caller A
    let (phone_b, addr_b) = phone().await; // secure (SAVP) callee B

    // A offers plaintext; the profile asks for a secure far leg. B answers RTP/SAVP with its key.
    let offer = engine_a
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ha-savp".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
    let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
    let engine_far = offer_reply.remote_rtp; // engine's B-facing port
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let answer = engine_a
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ha-savp".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_answer_sdp(addr_b, &b_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;

    // Sanity: the bridge relays on A (A plaintext → B SRTP, decryptable with the engine's key).
    let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
    let from_a = rtp_packet(100, 0x0A0A_0A0A);
    phone_a.send_to(&from_a, engine_near).await.expect("a send");
    let (srtp, _) = recv(&phone_b).await;
    let mut recovered = Vec::new();
    b_decrypt
        .unprotect(&srtp, &mut recovered)
        .expect("B decrypts on A");
    assert_eq!(recovered, from_a);

    // Checkpoint the secure call → the blob carries the secure section (peer key + bridge flows).
    let CmdResult::Checkpoint { snapshot } = engine_a
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "ha-savp".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("expected a checkpoint result");
    };
    let parsed = crate::ha::CallSnapshot::from_json(&snapshot).expect("parse blob");
    let secure = parsed
        .secure
        .expect("the snapshot carries the secure section");
    assert_eq!(secure.far_remote_crypto.suite, "AES_CM_128_HMAC_SHA1_80");
    assert!(
        !secure.bridge_flows.is_empty(),
        "bridge flow plans captured"
    );

    // Node A dies: delete frees its ports.
    engine_a
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "ha-savp".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(engine_a);

    // Node B (same range) restores the secure call and rebuilds the SRTP bridge at the same ports.
    let engine_b = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    tokio::spawn(run_redirect_dispatcher(
        engine_b.datapath().rx(),
        engine_b.bridge(),
        engine_b.media(),
        engine_b.ws(),
        engine_b.conference(),
        None,
    ));
    assert!(
        matches!(
            engine_b.handle(CLIENT, Command::Restore { snapshot }).await,
            CmdResult::Ok { .. }
        ),
        "secure restore succeeds on the standby"
    );

    // Secure media resumes through B at the unchanged ports.
    // A → engine_near → B receives SRTP (still decryptable with the engine's original key).
    let from_a2 = rtp_packet(101, 0x0A0A_0A0A);
    phone_a
        .send_to(&from_a2, engine_near)
        .await
        .expect("a send 2");
    let (srtp2, _) = recv(&phone_b).await;
    let mut recovered2 = Vec::new();
    b_decrypt
        .unprotect(&srtp2, &mut recovered2)
        .expect("B decrypts through the restored bridge");
    assert_eq!(
        recovered2, from_a2,
        "A→B secure relay resumes on the standby"
    );

    // B → engine_far as SRTP (B's key) → bridge decrypts → A receives plaintext.
    let from_b = rtp_packet(200, 0x0B0B_0B0B);
    let mut b_encrypt = SrtpContext::from_key_material(&b_key.key);
    let mut srtp_b = Vec::new();
    b_encrypt.protect(&from_b, &mut srtp_b).expect("B encrypts");
    phone_b.send_to(&srtp_b, engine_far).await.expect("b send");
    let (recovered_a, _) = recv(&phone_a).await;
    assert_eq!(
        recovered_a, from_b,
        "B→A secure relay resumes on the standby"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_resumes_a_transcode_call_on_a_standby() {
    use crate::srtp_bridge::run_redirect_dispatcher;

    // Transcode warm-standby HA: a PCMU↔PCMA transcoding call is set up on node A, checkpointed,
    // torn down, then restored on node B which re-binds the same ports and rebuilds the
    // transcoding actor — and media transcodes through B (fresh actor state, same ports).
    let (min, max) = (49_000u16, 49_040u16);
    let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let engine_a = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    tokio::spawn(run_redirect_dispatcher(
        engine_a.datapath().rx(),
        engine_a.bridge(),
        engine_a.media(),
        engine_a.ws(),
        engine_a.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    // A offers PCMU; B answers PCMA → near=PCMU, far=PCMA → the transcoding media slow path.
    let offer = engine_a
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ha-xcode".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    let engine_far = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;
    let answer = engine_a
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ha-xcode".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    assert!(
        engine_a.media().is_media_call("ha-xcode"),
        "resolves to a transcode call"
    );

    // Checkpoint carries both codecs; then A dies (delete frees ports).
    let CmdResult::Checkpoint { snapshot } = engine_a
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "ha-xcode".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("checkpoint");
    };
    let parsed = crate::ha::CallSnapshot::from_json(&snapshot).expect("parse blob");
    assert_eq!(parsed.near_codec.expect("near codec").encoding_name, "PCMU");
    assert_eq!(parsed.far_codec.expect("far codec").encoding_name, "PCMA");
    engine_a
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "ha-xcode".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(engine_a);

    // Node B restores the transcode call and rebuilds the actor at the same ports.
    let engine_b = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    tokio::spawn(run_redirect_dispatcher(
        engine_b.datapath().rx(),
        engine_b.bridge(),
        engine_b.media(),
        engine_b.ws(),
        engine_b.conference(),
        None,
    ));
    assert!(
        matches!(
            engine_b.handle(CLIENT, Command::Restore { snapshot }).await,
            CmdResult::Ok { .. }
        ),
        "transcode restore succeeds on the standby"
    );
    assert!(
        engine_b.media().is_media_call("ha-xcode"),
        "the transcoding actor is rebuilt on the standby"
    );

    // A → engine_near → transcode → B receives A-law (PT 8), not the original µ-law.
    let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
    phone_a.send_to(&from_a, engine_near).await.expect("a send");
    let (transcoded, _) = recv(&phone_b).await;
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&transcoded).expect("parse");
    assert_eq!(
        parsed.payload_type, 8,
        "B receives A-law (PT 8) through the restored actor"
    );

    // B → engine_far → transcode → A receives µ-law (PT 0).
    let from_b = g711_rtp(8, 200, 0x0B0B_0B0B, 0x55);
    phone_b.send_to(&from_b, engine_far).await.expect("b send");
    let (back, _) = recv(&phone_a).await;
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&back).expect("parse");
    assert_eq!(
        parsed.payload_type, 0,
        "A receives µ-law (PT 0) through the restored actor"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_resumes_a_secure_transcode_call_on_a_standby() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_srtp::{SrtpContext, StreamRollover};

    // Secure-transcode warm-standby HA (`PipelineKind::SrtpMedia`, BGCF/SBC PSTN breakout): a
    // plaintext G.711 µ-law near leg (A) ↔ a secure RTP/SAVP G.711 A-law far leg (B). The engine
    // decrypts B's SRTP, transcodes, and encrypts toward B (and the reverse) in one actor. We set
    // it up on node A, drive a secure packet so the inbound SRTP rollover records B's SSRC,
    // checkpoint (capturing the peer's key + the actor's live rollover, from the media actor — not
    // the SRTP bridge), tear node A down, then restore on node B which re-binds the same ports,
    // rebuilds the transcode actor AND the shared SecureLeg (re-keyed + rollover re-seeded), and
    // proves media transcodes+crypts through B both ways with the SRTP rollover *continued* (no
    // ROC reset → no two-time-pad, RFC 3711 §3.3.1).
    let (min, max) = (49_100u16, 49_160u16);
    let bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let b_ssrc = 0x0B0B_0B0Bu32;

    let engine_a = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    tokio::spawn(run_redirect_dispatcher(
        engine_a.datapath().rx(),
        engine_a.bridge(),
        engine_a.media(),
        engine_a.ws(),
        engine_a.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await; // plain G.711 µ-law (PSTN) A
    let (phone_b, addr_b) = phone().await; // secure G.711 A-law (SAVP) B

    // A offers plaintext PCMU; the profile secures the far leg. B answers RTP/SAVP PCMA with its
    // key → near = PCMU (8 kHz), far = PCMA (8 kHz), secure ⇒ the secure-transcode media path.
    let offer = engine_a
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ha-savp-xcode".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
    let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
    let engine_far = offer_reply.remote_rtp; // engine's B-facing port
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let answer = engine_a
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ha-savp-xcode".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_answer_codec(addr_b, 8, "PCMA", &b_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    assert!(
        engine_a.media().is_media_call("ha-savp-xcode"),
        "secure + transcode resolves to the media slow path"
    );

    // A → engine(near): plaintext PCMU → transcode PCMU→PCMA → encrypt → B gets SRTP it decrypts.
    let from_a0 = g711_rtp(0, 10, 0x0A0A_0A0A, 0xFF);
    phone_a
        .send_to(&from_a0, engine_near)
        .await
        .expect("a send 0");
    let (srtp0, _) = recv(&phone_b).await;
    assert_ne!(srtp0, from_a0, "B receives SRTP, not plaintext");

    // B → engine(far): PCMA SRTP (B's key), seq 60000 → the actor decrypts (recording B's SSRC +
    // highest_seq in the inbound SRTP rollover), transcodes PCMA→PCMU, and A gets plaintext.
    let mut b_encrypt = SrtpContext::from_key_material(&b_key.key);
    let mut srtp_b = Vec::new();
    b_encrypt
        .protect(&g711_rtp(8, 60_000, b_ssrc, 0x55), &mut srtp_b)
        .expect("B encrypts");
    phone_b.send_to(&srtp_b, engine_far).await.expect("b send");
    let (plain_a, _) = recv(&phone_a).await;
    let g711 = siphon_rtp_media::rtp::RtpPacket::parse(&plain_a).expect("parse plaintext");
    assert_eq!(g711.payload_type, 0, "A receives transcoded G.711 µ-law");

    // Checkpoint the secure-transcode call → the blob carries the secure section, sourced from the
    // media actor: the peer's key, the live SRTP rollover, and NO bridge flows (SrtpMedia crypts
    // inside the actor).
    let CmdResult::Checkpoint { snapshot } = engine_a
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "ha-savp-xcode".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("expected a checkpoint result");
    };
    let parsed = crate::ha::CallSnapshot::from_json(&snapshot).expect("parse blob");
    assert_eq!(
        parsed.pipeline,
        crate::ha::PipelineSnapshot::SrtpMedia,
        "snapshot pipeline is SrtpMedia"
    );
    assert_eq!(
        parsed.near_codec.as_ref().expect("near").encoding_name,
        "PCMU"
    );
    assert_eq!(
        parsed.far_codec.as_ref().expect("far").encoding_name,
        "PCMA"
    );
    let secure = parsed
        .secure
        .as_ref()
        .expect("the snapshot carries the secure section");
    assert_eq!(secure.far_remote_crypto.suite, "AES_CM_128_HMAC_SHA1_80");
    assert!(
        secure.bridge_flows.is_empty(),
        "a secure transcode has no in-datapath bridge flows (crypts in the actor)"
    );
    let inbound = secure
        .rollover
        .inbound_rtp
        .iter()
        .find(|stream| stream.ssrc == b_ssrc)
        .copied()
        .expect("B's inbound SRTP rollover was captured");
    assert_eq!(
        inbound.highest_seq,
        Some(60_000),
        "the captured rollover anchors at B's last-seen sequence"
    );

    // Simulate a checkpoint taken *after* B's stream had rolled over 7 times (RFC 3711 §3.3.1):
    // bump the captured inbound ROC to 7. A correct restore must carry this across so decryption
    // keeps computing the right packet index — a reset to 0 would authenticate against the wrong
    // keystream (a two-time-pad / auth failure).
    let mut mutated = parsed.clone();
    mutated
        .secure
        .as_mut()
        .expect("secure section")
        .rollover
        .inbound_rtp
        .iter_mut()
        .find(|stream| stream.ssrc == b_ssrc)
        .expect("B inbound entry")
        .roc = 7;
    let blob = mutated.to_json().expect("reserialize the mutated snapshot");

    // Node A dies: delete frees its ports, then drop the engine.
    engine_a
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "ha-savp-xcode".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    drop(engine_a);

    // Node B (same range) restores the secure-transcode call and rebuilds the actor + SecureLeg.
    let engine_b = Engine::new(UdpLoopbackDatapath::with_port_range(bind, min, max));
    tokio::spawn(run_redirect_dispatcher(
        engine_b.datapath().rx(),
        engine_b.bridge(),
        engine_b.media(),
        engine_b.ws(),
        engine_b.conference(),
        None,
    ));
    assert!(
        matches!(
            engine_b
                .handle(CLIENT, Command::Restore { snapshot: blob })
                .await,
            CmdResult::Ok { .. }
        ),
        "secure-transcode restore succeeds on the standby"
    );
    assert!(
        engine_b.media().is_media_call("ha-savp-xcode"),
        "the secure-transcode actor is rebuilt on the standby"
    );

    // Re-checkpoint node B immediately: the rebuilt SecureLeg must have been *seeded* — the inbound
    // ROC is still 7 and anchored at seq 60000, proving the rollover continued (no reset).
    let CmdResult::Checkpoint { snapshot: reblob } = engine_b
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "ha-savp-xcode".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await
    else {
        panic!("expected a checkpoint result on the standby");
    };
    let reparsed = crate::ha::CallSnapshot::from_json(&reblob).expect("parse standby blob");
    let reinbound = reparsed
        .secure
        .as_ref()
        .expect("standby secure section")
        .rollover
        .inbound_rtp
        .iter()
        .find(|stream| stream.ssrc == b_ssrc)
        .copied()
        .expect("B's inbound rollover survived the restore");
    assert_eq!(
        reinbound.roc, 7,
        "the SRTP rollover counter continued (no ROC reset)"
    );
    assert_eq!(
        reinbound.highest_seq,
        Some(60_000),
        "the rollover anchor continued across the restore"
    );

    // Secure media resumes through B at the unchanged ports, both ways. To prove the *continuity*
    // (not just that some packet decrypts), advance the peer's own SRTP state to the same ROC=7 the
    // failover happened at — a real B would be there — so its next packet authenticates against
    // ROC=7. It decrypts on the standby ONLY IF the restore kept ROC=7: a reset to ROC=0 would
    // compute the wrong packet index and fail auth (a two-time-pad, RFC 3711 §3.3.1).
    b_encrypt.seed_stream(StreamRollover {
        ssrc: b_ssrc,
        roc: 7,
        highest_seq: Some(60_000),
    });
    // B → engine(far): PCMA SRTP (B's key) at seq 60001 / ROC 7 → decrypt → transcode → A gets PCMU.
    let mut srtp_b2 = Vec::new();
    b_encrypt
        .protect(&g711_rtp(8, 60_001, b_ssrc, 0x55), &mut srtp_b2)
        .expect("B encrypts 2");
    phone_b
        .send_to(&srtp_b2, engine_far)
        .await
        .expect("b send 2");
    let (plain_a2, _) = recv(&phone_a).await;
    let g711_2 = siphon_rtp_media::rtp::RtpPacket::parse(&plain_a2).expect("parse plaintext 2");
    assert_eq!(
        g711_2.payload_type, 0,
        "B→A secure transcode resumes on the standby at the continued ROC (A gets µ-law)"
    );

    // A → engine(near): plaintext PCMU → transcode PCMU→PCMA → encrypt → B gets SRTP it decrypts.
    let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
    phone_a.send_to(&from_a, engine_near).await.expect("a send");
    let (srtp_to_b, from) = recv(&phone_b).await;
    assert_eq!(from, engine_far, "media leaves the engine's B-facing port");
    assert_ne!(srtp_to_b, from_a, "B receives SRTP, not plaintext");
    let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
    let mut recovered = Vec::new();
    b_decrypt
        .unprotect(&srtp_to_b, &mut recovered)
        .expect("B decrypts the engine's SRTP through the restored actor");
    let to_b = siphon_rtp_media::rtp::RtpPacket::parse(&recovered).expect("parse decrypted");
    assert_eq!(
        to_b.payload_type, 8,
        "A→B secure transcode resumes on the standby (B gets A-law)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn savp_bridge_relays_avp_plaintext_to_savp_srtp_both_ways() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_srtp::SrtpContext;

    // Scenario 1: A is plain RTP/AVP, the control asks for a secure RTP/SAVP far leg, and the
    // engine bridges the two — SRTP terminated on B, plaintext relayed to A. Driven end-to-end
    // through the control plane with the redirect dispatcher live.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await; // plain (AVP) caller A
    let (phone_b, addr_b) = phone().await; // secure (SAVP) callee B

    // A offers plaintext RTP/AVP; the profile asks for a secure far leg (rtpengine model).
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "savp-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile,
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("parse offer reply");
    assert!(offer_reply.secure, "the engine offers RTP/SAVP to B");
    let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
    let far_addr = offer_reply.remote_rtp; // the engine's B-facing endpoint

    // B answers RTP/SAVP with its own SDES key.
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "savp-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_answer_sdp(addr_b, &b_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer_reply = sdp::parse(&ok_sdp_text(&answer)).expect("parse answer reply");
    assert!(!answer_reply.secure, "the answer to A is plaintext RTP/AVP");
    assert!(
        answer_reply.crypto.is_empty(),
        "no crypto leaks to the plain leg"
    );
    let near_addr = answer_reply.remote_rtp; // the engine's A-facing endpoint

    // A → engine(near) → bridge encrypts → B receives SRTP, decryptable with the engine's key.
    let from_a = rtp_packet(100, 0x0A0A_0A0A);
    phone_a.send_to(&from_a, near_addr).await.expect("a send");
    let (srtp, from) = recv(&phone_b).await;
    assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
    assert_ne!(srtp, from_a, "B receives SRTP, not plaintext");
    let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
    let mut recovered = Vec::new();
    b_decrypt
        .unprotect(&srtp, &mut recovered)
        .expect("B decrypts the engine's SRTP");
    assert_eq!(recovered, from_a);

    // B → engine(far) as SRTP (B's key) → bridge decrypts → A receives plaintext.
    let from_b = rtp_packet(200, 0x0B0B_0B0B);
    let mut b_encrypt = SrtpContext::from_key_material(&b_key.key);
    let mut srtp_b = Vec::new();
    b_encrypt.protect(&from_b, &mut srtp_b).expect("B encrypts");
    phone_b.send_to(&srtp_b, far_addr).await.expect("b send");
    let (recovered_a, from) = recv(&phone_a).await;
    assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
    assert_eq!(recovered_a, from_b, "A receives the decrypted plaintext");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secure_bridge_carrying_media_is_not_reaped_but_a_silent_one_still_is() {
    // The same gap R7 named on the takeover pipeline, on the SDES bridge. Both of a bridged
    // call's legs are `Redirect`, so no `Forward` rule stamps anywhere and the datapath's
    // `Redirect` arm deliberately does not either — without the bridge stamping for itself, a
    // secure bridge call is reaped at the media timeout however much audio is crossing it.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_srtp::SrtpContext;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "savp-idle".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("parse offer reply");
    let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "savp-idle".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_answer_sdp(addr_b, &b_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("parse answer reply")
        .remote_rtp;

    // Past the timeout first, so surviving the sweep can only be the packet below.
    engine.datapath().advance_clock(10);
    let from_a = rtp_packet(100, 0x0A0A_0A0A);
    phone_a.send_to(&from_a, near_addr).await.expect("a send");
    // B receiving it is the synchronisation point: the datagram cleared the gate and the crypto.
    let (srtp, _from) = recv(&phone_b).await;
    let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
    let mut recovered = Vec::new();
    b_decrypt
        .unprotect(&srtp, &mut recovered)
        .expect("B decrypts");
    assert_eq!(recovered, from_a);

    assert!(
        engine.reap_idle(5, 0).await.is_empty(),
        "a secure bridge carrying audio is not idle"
    );

    engine.datapath().advance_clock(10);
    assert_eq!(
        engine.reap_idle(5, 0).await,
        vec!["savp-idle".to_string()],
        "and one that has genuinely gone quiet is still reaped"
    );
}

/// An `RTP/SAVP` answer SDP advertising AMR-WB (PT 96, 16 kHz) at `addr` with `crypto` (rtcp-mux).
#[cfg(feature = "amr")]
fn savp_amr_wb_answer_sdp(addr: SocketAddr, crypto: &CryptoAttribute) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=rtcp-mux\r\na={crypto_line}\r\n",
        ip = addr.ip(),
        port = addr.port(),
        crypto_line = crypto.to_attribute_value(),
    )
}

/// BGCF/SBC, the secure transcode: a secure `RTP/SAVP` **AMR-WB (16 kHz)** far leg ↔ a plaintext
/// `RTP/AVP` **G.711 µ-law (8 kHz)** near leg. The engine decrypts B's SRTP, transcodes (16↔8 kHz
/// resample), and encrypts toward B — and the reverse — in one `MediaCall` (`PipelineKind::SrtpMedia`),
/// driven end to end through the control plane + redirect dispatcher. `amr`-feature-gated.
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn savp_amr_wb_far_leg_transcodes_to_plain_g711_both_ways() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_srtp::SrtpContext;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await; // plain G.711 (PSTN) side
    let (phone_b, addr_b) = phone().await; // secure AMR-WB (VoLTE) side

    // A offers plaintext G.711; the profile asks the engine to secure the far (B) leg.
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "savp-xcode".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile,
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
    assert!(offer_reply.secure, "engine offers RTP/SAVP to B");
    let engine_far_key = *offer_reply.crypto.first().expect("engine a=crypto to B");
    let far_addr = offer_reply.remote_rtp;

    // B answers RTP/SAVP AMR-WB with its own key → near = G.711 (8 kHz), far = AMR-WB (16 kHz),
    // secure ⇒ the secure transcoding media slow path.
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "savp-xcode".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_amr_wb_answer_sdp(addr_b, &b_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    assert!(
        engine.media().is_media_call("savp-xcode"),
        "secure + transcode resolves to the media slow path"
    );

    // A → engine(near): plaintext G.711 in; B receives SRTP that decrypts to transcoded AMR-WB.
    let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
    phone_a.send_to(&from_a, near_addr).await.expect("a send");
    let (srtp, from) = recv(&phone_b).await;
    assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
    assert_ne!(srtp, from_a, "B receives SRTP, not plaintext");
    let mut b_decrypt = SrtpContext::from_key_material(&engine_far_key.key);
    let mut amr = Vec::new();
    b_decrypt
        .unprotect(&srtp, &mut amr)
        .expect("B decrypts the engine's SRTP");
    let amr_rtp = siphon_rtp_media::rtp::RtpPacket::parse(&amr).expect("parse decrypted");
    assert_eq!(amr_rtp.payload_type, 96, "B receives AMR-WB (PT 96)");
    assert!(!amr_rtp.payload.is_empty(), "AMR-WB egress carries a frame");

    // B → engine(far): AMR-WB SRTP (B's key) in; A receives plaintext transcoded G.711 µ-law.
    let mut b_encrypt = SrtpContext::from_key_material(&b_key.key);
    let mut srtp_b = Vec::new();
    b_encrypt
        .protect(&amr_wb_rtp(7, 0x0B0B_0B0B), &mut srtp_b)
        .expect("B encrypts");
    phone_b.send_to(&srtp_b, far_addr).await.expect("b send");
    let (plain_a, from) = recv(&phone_a).await;
    assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
    let g711 = siphon_rtp_media::rtp::RtpPacket::parse(&plain_a).expect("parse plaintext");
    assert_eq!(g711.payload_type, 0, "A receives G.711 µ-law (PT 0)");
    assert_eq!(g711.payload.len(), 160, "20 ms at 8 kHz, 1 byte/sample");
}

/// A minimal RTCP sender-report-shaped datagram (version 2, PT 200) carrying `ssrc`.
fn rtcp_sr(ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 200, 0x00, 0x00];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[0x33; 16]);
    packet
}

/// The BGCF/SBC secure transcode **without rtcp-mux**: the companion RTCP endpoints are redirected
/// into the media actor and SRTCP-(de)crypted through the shared SecureLeg (RFC 3711 / RFC 5761) —
/// B's SRTCP is decrypted and relayed plaintext to A's RTCP port, and A's plaintext RTCP is
/// encrypted toward B. Driven end to end through the control plane + redirect dispatcher.
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn savp_transcode_relays_non_muxed_srtcp_both_ways() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_srtp::srtcp::SrtcpContext;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    // Dedicated RTP + RTCP sockets per party (non-mux ⇒ RTCP on its own port).
    let (_phone_a, addr_a) = phone().await;
    let (rtcp_a, rtcp_a_addr) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let (rtcp_b, rtcp_b_addr) = phone().await;

    // A offers plaintext G.711, non-mux, advertising its RTCP socket; the profile secures the far leg.
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp:{rtcp}\r\n",
        ip = addr_a.ip(),
        port = addr_a.port(),
        rtcp = rtcp_a_addr.port(),
    );
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "savp-nonmux".into(),
                from_tag: "tag-a".into(),
                sdp: offer_sdp,
                profile,
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
    let engine_far_key = *offer_reply.crypto.first().expect("engine key to B");
    let far_rtp = offer_reply.remote_rtp;
    let far_rtcp = offer_reply.remote_rtcp;
    assert_ne!(
        far_rtcp, far_rtp,
        "non-mux: distinct RTCP port advertised to B"
    );

    // B answers RTP/SAVP AMR-WB, non-mux, advertising its RTCP socket + key.
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=rtcp:{rtcp}\r\na={crypto}\r\n",
        ip = addr_b.ip(),
        port = addr_b.port(),
        rtcp = rtcp_b_addr.port(),
        crypto = b_key.to_attribute_value(),
    );
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "savp-nonmux".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: answer_sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let near_rtcp = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtcp;
    assert!(
        engine.media().is_media_call("savp-nonmux"),
        "secure transcode resolves to the media slow path"
    );

    // B → A: B encrypts an RTCP SR with its key → engine far RTCP; A's RTCP socket gets plaintext.
    let b_sr = rtcp_sr(0xB0B0_B0B0);
    let mut b_srtcp = Vec::new();
    SrtcpContext::from_key_material(&b_key.key)
        .protect(&b_sr, &mut b_srtcp)
        .expect("B encrypt SRTCP");
    rtcp_b
        .send_to(&b_srtcp, far_rtcp)
        .await
        .expect("b rtcp send");
    let (relayed, from) = recv(&rtcp_a).await;
    assert_eq!(
        from, near_rtcp,
        "RTCP relayed from the engine's near RTCP port"
    );
    assert_eq!(relayed, b_sr, "A receives B's decrypted plaintext RTCP");

    // A → B: A's plaintext RTCP → engine near RTCP; B's RTCP socket gets SRTCP it can decrypt.
    let a_sr = rtcp_sr(0xA0A0_A0A0);
    rtcp_a.send_to(&a_sr, near_rtcp).await.expect("a rtcp send");
    let (srtcp, from) = recv(&rtcp_b).await;
    assert_eq!(from, far_rtcp, "engine transmits from its far RTCP port");
    assert_ne!(srtcp, a_sr, "toward B it is encrypted (SRTCP)");
    let mut recovered = Vec::new();
    SrtcpContext::from_key_material(&engine_far_key.key)
        .unprotect(&srtcp, &mut recovered)
        .expect("B decrypt SRTCP");
    assert_eq!(recovered, a_sr, "B recovers A's RTCP");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_mixes_two_participants_end_to_end() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_codec::Decoder as _;
    use siphon_rtp_dsp::EnergyVad;
    use siphon_rtp_media::rtp::RtpPacket;

    // Two callers join one room over the JSON control plane, exchange loud G.711, and each hears
    // the other's audio mixed back — the full path: join → endpoint alloc → Redirect → dispatcher
    // → mixer actor → 20 ms tick → egress.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    let join_a = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "room-1".into(),
                from_tag: "alice".into(),
                sdp: sdp_for(addr_a, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_a = sdp::parse(&ok_sdp_text(&join_a))
        .expect("A answer")
        .remote_rtp;
    let join_b = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "room-1".into(),
                from_tag: "bob".into(),
                sdp: sdp_for(addr_b, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_b = sdp::parse(&ok_sdp_text(&join_b))
        .expect("B answer")
        .remote_rtp;

    // Both speak loud G.711 (µ-law 0x00 ≈ full scale); fill the jitter buffers well past the
    // priming depth so there is a window during which each is heard.
    for sequence in 0..30 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x00), engine_a)
            .await
            .expect("a send");
        phone_b
            .send_to(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0x00), engine_b)
            .await
            .expect("b send");
    }

    // The 20 ms room ticker mixes and sends each participant the other's audio. The first frame
    // or two are silence (before the peer's jitter buffer primes), so scan a few frames.
    let mut decoder = G711::ulaw();
    let mut heard_loud = false;
    for _ in 0..8 {
        let (mix_a, from_a) = recv(&phone_a).await;
        assert_eq!(from_a, engine_a, "A hears the mix from its engine port");
        let packet = RtpPacket::parse(&mix_a).expect("A egress RTP");
        assert_eq!(packet.payload_type, 0, "G.711 µ-law egress");
        let mut pcm = vec![0i16; 320];
        let samples = decoder.decode(packet.payload, &mut pcm).expect("decode");
        if EnergyVad::energy(&pcm[..samples]) > 1_000_000 {
            heard_loud = true;
            break;
        }
    }
    assert!(
        heard_loud,
        "A hears B's loud audio (mixed-minus-self) within a few frames"
    );
    let (_mix_b, from_b) = recv(&phone_b).await;
    assert_eq!(from_b, engine_b, "B hears the mix from its engine port");

    // Leaving releases each participant; the empty room is torn down.
    for tag in ["alice", "bob"] {
        let left = engine
            .handle(
                CLIENT,
                Command::ConferenceLeave {
                    conference_id: "room-1".into(),
                    from_tag: tag.into(),
                },
            )
            .await;
        assert!(
            matches!(left, CmdResult::Ok { .. }),
            "{tag} leaves: {left:?}"
        );
    }
    assert!(
        !engine.conference().contains("room-1"),
        "empty room torn down"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_bridge_command_wires_two_rooms() {
    use crate::srtp_bridge::run_redirect_dispatcher;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    // Bridging non-existent rooms is an error.
    let missing = engine
        .handle(
            CLIENT,
            Command::ConferenceBridge {
                conference_id_a: "ghost-1".into(),
                conference_id_b: "ghost-2".into(),
                direction: BridgeDirection::Both,
            },
        )
        .await;
    assert!(
        matches!(missing, CmdResult::Error { .. }),
        "no such rooms: {missing:?}"
    );

    // Seat a participant in each of two rooms, then bridge them.
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    for (room, tag, addr) in [("room-x", "alice", addr_a), ("room-y", "bob", addr_b)] {
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
        assert!(
            matches!(joined, CmdResult::Ok { .. }),
            "{tag} joins {room}: {joined:?}"
        );
    }
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
    assert!(
        matches!(bridged, CmdResult::Ok { .. }),
        "rooms bridge: {bridged:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conference_reaps_idle_participants() {
    use crate::srtp_bridge::run_redirect_dispatcher;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let mut engine_a = addr_a; // overwritten with alice's engine port below
    for (tag, addr) in [("alice", addr_a), ("bob", addr_b)] {
        let joined = engine
            .handle(
                CLIENT,
                Command::ConferenceJoin {
                    conference_id: "room".into(),
                    from_tag: tag.into(),
                    sdp: sdp_for(addr, true),
                    role: ConferenceRole::Talker,
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        let port = sdp::parse(&ok_sdp_text(&joined))
            .expect("answer")
            .remote_rtp;
        if tag == "alice" {
            engine_a = port;
        }
    }

    // Advance the logical clock, then alice sends media (stamping her endpoint's activity); bob
    // stays silent. With idle_ticks = 3, bob is idle since tick 0 (now 4 ⇒ reaped) but alice's
    // activity is fresh (kept).
    engine.datapath().advance_clock(4);
    phone_a
        .send_to(&g711_rtp(0, 0, 0x0A0A_0A0A, 0x00), engine_a)
        .await
        .expect("a send");
    tokio::time::sleep(Duration::from_millis(30)).await; // let the datapath stamp activity

    assert_eq!(
        engine.reap_idle_conferences(3, 0).await,
        1,
        "the silent participant is reaped"
    );
    assert!(
        engine.conference().contains("room"),
        "the active participant keeps the room alive"
    );

    // Advance past alice's activity too — now the room drains and is torn down.
    engine.datapath().advance_clock(5);
    assert!(
        engine.reap_idle_conferences(3, 0).await >= 1,
        "the now-idle participant is reaped"
    );
    assert!(
        !engine.conference().contains("room"),
        "empty room torn down"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listen_only_conference_seat_is_not_reaped_for_being_silent() {
    // A webinar attendee joins `recvonly` and never sends a packet for the whole session — that is
    // the seat working as signalled, not a dead one. The same rule the two-party reaper applies:
    // silence is only evidence when the party said it would send.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "webinar".into(),
                from_tag: "attendee".into(),
                sdp: sdp_with_direction(addr, "recvonly"),
                role: ConferenceRole::Listener,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(joined, CmdResult::Ok { .. }), "seated: {joined:?}");

    engine.datapath().advance_clock(100);
    assert_eq!(
        engine.reap_idle_conferences(3, 1000).await,
        0,
        "a listen-only seat owes the room no media"
    );
    assert!(engine.conference().contains("webinar"), "room still up");

    engine.datapath().advance_clock(1000);
    assert!(
        engine.reap_idle_conferences(3, 1000).await >= 1,
        "and the held ceiling still frees an abandoned seat"
    );
}

/// Seat one µ-law participant in `conference_id` and return the engine port it sends to.
async fn seat_participant(
    engine: &Engine<UdpLoopbackDatapath>,
    conference_id: &str,
    tag: &str,
    addr: SocketAddr,
) -> SocketAddr {
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: conference_id.into(),
                from_tag: tag.into(),
                sdp: sdp_for(addr, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    sdp::parse(&ok_sdp_text(&joined))
        .expect("the room's answer")
        .remote_rtp
}

/// An 8 kHz mono WAV of `samples` constant-valued samples, as a `play_media` blob.
fn prompt_blob(samples: usize, value: i16) -> Vec<u8> {
    use siphon_rtp_media::fanout::MediaSink as _;
    let mut recorder = siphon_rtp_media::wav::WavRecorder::new(8000, 1);
    recorder.write_pcm(&vec![value; samples]);
    recorder.into_wav()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_room_playback_is_heard_by_the_participants() {
    // Nothing could be played into a room at all: every media verb resolves through `self.calls`,
    // which a conference never enters, so `play_media` against a room id answered `unknown call`.
    // An entry tone, a "this conference is being recorded" announcement and music for a lone
    // participant are all this.
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
    let (phone, addr) = phone().await;
    let _engine_port = seat_participant(&engine, "room-play", "alice", addr).await;

    let played = engine
        .handle(
            CLIENT,
            Command::ConferencePlay {
                conference_id: "room-play".into(),
                source: PlayMediaSource::Blob {
                    data: prompt_blob(8000, 6000),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                gain_decibels: None,
            },
        )
        .await;
    let play_id = match played {
        CmdResult::Ok {
            play_id: Some(id), ..
        } => id,
        other => panic!("a room playback accepts with a play_id, got {other:?}"),
    };

    // The lone participant hears the announcement even though nobody in the room is talking —
    // which is the case the mixer's `external` input exists for: heard by everyone, mixed against
    // nobody.
    let mut heard = false;
    for _ in 0..40u16 {
        let mut buffer = [0u8; 2048];
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone.recv_from(&mut buffer)).await
        else {
            continue;
        };
        let parsed =
            siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse room egress");
        if parsed
            .payload
            .iter()
            .any(|&byte| byte != 0xFF && byte != 0x7F)
        {
            heard = true;
            break;
        }
    }
    assert!(heard, "the participant hears the room announcement");

    let stopped = engine
        .handle(
            CLIENT,
            Command::ConferenceStopPlay {
                conference_id: "room-play".into(),
                play_id: Some(play_id),
            },
        )
        .await;
    assert!(
        matches!(stopped, CmdResult::Ok { .. }),
        "stop accepted: {stopped:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_room_playback_reports_its_end_against_the_conference_not_a_call() {
    // A room playback is not on a call, so the completion correlates by `conference_id` and
    // leaves `call_id` empty rather than smuggling a room id into a field that means something
    // else.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (_phone, addr) = phone().await;
    seat_participant(&engine, "room-end", "alice", addr).await;

    let played = engine
        .handle(
            CLIENT,
            Command::ConferencePlay {
                conference_id: "room-end".into(),
                source: PlayMediaSource::Blob {
                    data: prompt_blob(320, 4000),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                gain_decibels: None,
            },
        )
        .await;
    let play_id = match played {
        CmdResult::Ok {
            play_id: Some(id),
            duration_ms: Some(40),
            ..
        } => id,
        other => panic!("expected a 40 ms accept with a play_id, got {other:?}"),
    };

    let mut finished = None;
    for _ in 0..60u16 {
        match timeout(Duration::from_millis(200), events.recv_async()).await {
            Ok(Ok(Event::PlayFinished {
                call_id,
                conference_id,
                play_id: id,
                reason,
                ..
            })) => {
                finished = Some((call_id, conference_id, id, reason));
                break;
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    let (call_id, conference_id, id, reason) = finished.expect("the room playback reports its end");
    assert_eq!(id, play_id);
    assert_eq!(reason, siphon_rtp_proto::PlayEndReason::Completed);
    assert_eq!(
        conference_id.as_deref(),
        Some("room-end"),
        "correlated by room"
    );
    assert!(call_id.is_empty(), "and not by a call it never ran on");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn room_playback_verbs_refuse_an_unknown_room_or_play_id() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    seat_participant(&engine, "room-errors", "alice", addr).await;

    for result in [
        engine
            .handle(
                CLIENT,
                Command::ConferencePlay {
                    conference_id: "no-such-room".into(),
                    source: PlayMediaSource::Blob {
                        data: prompt_blob(160, 1),
                    },
                    repeat_times: None,
                    start_pos_ms: None,
                    duration_ms: None,
                    gain_decibels: None,
                },
            )
            .await,
        engine
            .handle(
                CLIENT,
                Command::ConferenceStopPlay {
                    conference_id: "no-such-room".into(),
                    play_id: Some(1),
                },
            )
            .await,
        engine
            .handle(
                CLIENT,
                Command::ConferenceSetPlayGain {
                    conference_id: "no-such-room".into(),
                    play_id: 1,
                    gain_decibels: -6,
                },
            )
            .await,
        // A real room, but an id that is not running: a hollow success would leave a controller
        // believing it had stopped something it had not.
        engine
            .handle(
                CLIENT,
                Command::ConferenceStopPlay {
                    conference_id: "room-errors".into(),
                    play_id: Some(9999),
                },
            )
            .await,
        engine
            .handle(
                CLIENT,
                Command::ConferenceSetPlayGain {
                    conference_id: "room-errors".into(),
                    play_id: 9999,
                    gain_decibels: -6,
                },
            )
            .await,
    ] {
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "expected a refusal, got {result:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_room_recording_captures_the_mix_and_reports_the_finished_file() {
    // Nothing could record a room either. This taps the *listener* mix — what a listener hears,
    // bridged audio and announcements included — through the same streaming WAV writer a call
    // recording uses, so both produce the same file and the same completion event.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone, addr) = phone().await;
    let engine_port = seat_participant(&engine, "room-rec", "alice", addr).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let started = engine
        .handle(
            CLIENT,
            Command::ConferenceStartRecording {
                conference_id: "room-rec".into(),
                path: None,
                recording_dir: Some(dir.path().to_string_lossy().into_owned()),
                max_duration_ms: None,
                silence_ms: None,
            },
        )
        .await;
    let recording_id = match started {
        CmdResult::Ok {
            recording_id: Some(id),
            ..
        } => id,
        other => panic!("a room recording accepts with a recording_id, got {other:?}"),
    };

    // Alice talks into the room.
    for sequence in 0..12u16 {
        phone
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x20), engine_port)
            .await
            .expect("send");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let stopped = engine
        .handle(
            CLIENT,
            Command::ConferenceStopRecording {
                conference_id: "room-rec".into(),
                recording_id: Some(recording_id.clone()),
            },
        )
        .await;
    assert!(
        matches!(stopped, CmdResult::Ok { .. }),
        "stop accepted: {stopped:?}"
    );

    let mut finished = None;
    for _ in 0..60u16 {
        match timeout(Duration::from_millis(200), events.recv_async()).await {
            Ok(Ok(Event::RecordingFinished {
                conference_id,
                recording_id: id,
                path,
                duration_ms,
                reason,
                ..
            })) => {
                finished = Some((conference_id, id, path, duration_ms, reason));
                break;
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    let (conference_id, id, path, duration_ms, reason) =
        finished.expect("a recording_finished event arrives");
    assert_eq!(id, recording_id);
    assert_eq!(conference_id.as_deref(), Some("room-rec"));
    assert_eq!(reason, siphon_rtp_proto::RecordingEndReason::Stopped);
    assert!(duration_ms > 0, "the room mix was recorded");

    let bytes = std::fs::read(path.expect("the event names the file")).expect("read");
    let parsed = siphon_rtp_media::player::WavSource::parse(&bytes)
        .expect("the finished file is a valid WAV");
    assert_eq!(
        parsed.sample_rate_hz(),
        crate::conference::WIDEBAND_RECORDING_RATE_HZ,
        "a room recording is pinned to one rate for its lifetime"
    );
    assert_eq!(parsed.channels(), 1);
    assert!(
        !parsed.samples().is_empty(),
        "the header was finalized with the audio it holds"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_room_recording_refuses_an_unknown_room_and_an_unwritable_path() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    seat_participant(&engine, "room-rec-errors", "alice", addr).await;
    let dir = tempfile::tempdir().expect("tempdir");

    let unknown = engine
        .handle(
            CLIENT,
            Command::ConferenceStartRecording {
                conference_id: "no-such-room".into(),
                path: None,
                recording_dir: Some(dir.path().to_string_lossy().into_owned()),
                max_duration_ms: None,
                silence_ms: None,
            },
        )
        .await;
    assert!(matches!(unknown, CmdResult::Error { .. }));

    let unwritable = engine
        .handle(
            CLIENT,
            Command::ConferenceStartRecording {
                conference_id: "room-rec-errors".into(),
                path: Some(
                    dir.path()
                        .join("no-such-directory")
                        .join("room.wav")
                        .to_string_lossy()
                        .into_owned(),
                ),
                recording_dir: None,
                max_duration_ms: None,
                silence_ms: None,
            },
        )
        .await;
    match unwritable {
        CmdResult::Error { reason } => assert!(reason.contains("open"), "{reason}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(
        engine.recordings.is_empty(),
        "nothing was registered for a start that failed"
    );
}

#[tokio::test]
async fn conference_join_negotiates_sdes_srtp() {
    // A participant offering RTP/SAVP + a=crypto is answered with RTP/SAVP + the engine's own
    // a=crypto (SDES-SRTP secure conference leg).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let peer_crypto = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "secure-room".into(),
                from_tag: "alice".into(),
                sdp: savp_answer_sdp(addr, &peer_crypto),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&joined)).expect("answer");
    assert!(answer.secure, "the engine answers RTP/SAVP");
    assert!(
        !answer.crypto.is_empty(),
        "the engine advertises its own a=crypto"
    );
}

#[tokio::test]
async fn conference_join_accepts_a_secure_text_participant() {
    // A participant offering plaintext audio + a SECURE (RTP/SAVP + a=crypto) `m=text` (RFC 4103)
    // section is seated with a per-participant text `SecureLeg`, and the answer anchors the text
    // stream as `RTP/SAVP` on a non-zero port carrying the engine's OWN text a=crypto (never the
    // participant's) — RFC 9071 secure conference text, no longer declined.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_audio, audio_addr) = phone().await;
    let (_phone_text, text_addr) = phone().await;
    let text_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen text key");
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {aport} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
             m=text {tport} RTP/SAVP 98 99\r\na=rtpmap:98 red/1000\r\na=rtpmap:99 t140/1000\r\na={crypto}\r\n",
        ip = audio_addr.ip(),
        aport = audio_addr.port(),
        tport = text_addr.port(),
        crypto = text_key.to_attribute_value(),
    );
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "secure-text-room".into(),
                from_tag: "alice".into(),
                sdp: offer,
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer_sdp = ok_sdp_text(&joined);
    let answer = sdp::parse(&answer_sdp).expect("answer");
    let text = answer.text.expect("the answer anchors an m=text section");
    assert!(
        text.secure,
        "the engine answers RTP/SAVP for the text stream"
    );
    assert_ne!(
        text.remote_rtp.port(),
        0,
        "secure conference text is accepted (non-zero m=text port), not declined"
    );
    let engine_text_crypto = text
        .crypto
        .first()
        .copied()
        .expect("the engine advertises its own text a=crypto");
    assert_ne!(
        engine_text_crypto.key, text_key.key,
        "the engine mints its own text key, never echoing the participant's"
    );
    // The audio stays plaintext (RTP/AVP) — the two streams are secured independently.
    assert!(!answer.secure, "the audio leg stays plaintext RTP/AVP");
}

/// A G.711 RTP packet (160-sample frame) for transcode tests.
fn g711_rtp(payload_type: u8, sequence: u16, ssrc: u32, payload_byte: u8) -> Vec<u8> {
    let mut packet = vec![0x80, payload_type];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[payload_byte; 160]);
    packet
}

/// An SDP advertising a single static audio codec (mux), for transcode answers.
fn sdp_single_codec(rtp: SocketAddr, payload_type: u8, name: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {pt}\r\na=rtpmap:{pt} {name}/8000\r\na=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
        pt = payload_type,
    )
}

/// Encode 20 ms of 16 kHz PCM into an RFC 4867 octet-aligned AMR-WB RTP packet (PT 96) — what a
/// VoLTE UE puts on the wire. `amr`-feature-gated (patent-licensed — docs/codec-licensing.md).
#[cfg(feature = "amr")]
fn amr_wb_rtp(sequence: u16, ssrc: u32) -> Vec<u8> {
    use siphon_rtp_codec::factory::{encoder_for, CodecSpec};
    let mut encoder =
        encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("amr-wb encoder");
    let pcm: Vec<i16> = (0..320)
        .map(|i| ((i as f32 * 0.20).sin() * 6000.0) as i16)
        .collect();
    let mut amr_payload = vec![0u8; 256];
    let written = encoder
        .encode(&pcm, &mut amr_payload)
        .expect("encode amr-wb");
    let mut packet = vec![0x80, 96];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 320).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&amr_payload[..written]);
    packet
}

/// BGCF/SBC PSTN breakout, end to end through the control plane: A offers VoLTE **AMR-WB (16 kHz)**,
/// B answers PSTN **G.711a (8 kHz)**. The codec + clock-rate mismatch resolves to the media slow
/// path, which redirects both legs to a transcoding actor (decode → 16↔8 kHz resample → re-encode).
/// Proves AMR-WB RTP in → G.711a RTP out (and the reverse) over the real datapath + redirect
/// dispatcher — the first scenario worthy of a live siphon-sip rtpengine trial. `amr`-feature-gated.
#[cfg(feature = "amr")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_transcodes_amr_wb_to_g711a_end_to_end() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    // A offers AMR-WB on dynamic PT 96 at 16 kHz (the VoLTE leg).
    let amr_offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=rtcp-mux\r\n",
        ip = addr_a.ip(),
        port = addr_a.port(),
    );
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "volte-pstn".into(),
                from_tag: "tag-a".into(),
                sdp: amr_offer,
                profile: Default::default(),
            },
        )
        .await;
    let far_addr = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;

    // B answers G.711a only → near = AMR-WB (16 kHz), far = PCMA (8 kHz) → transcode + resample.
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "volte-pstn".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    assert!(
        engine.media().is_media_call("volte-pstn"),
        "AMR-WB↔G.711a resolves to the transcoding media slow path"
    );

    // A → engine(near): AMR-WB in; B receives genuinely transcoded G.711a (PT 8, 160 bytes @ 8 kHz).
    phone_a
        .send_to(&amr_wb_rtp(0, 0xAAAA_AAAA), near_addr)
        .await
        .expect("a send amr-wb");
    let (transcoded, from) = recv(&phone_b).await;
    assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&transcoded).expect("parse");
    assert_eq!(parsed.payload_type, 8, "B receives G.711a (PT 8)");
    assert_eq!(parsed.payload.len(), 160, "20 ms at 8 kHz, 1 byte/sample");
    assert!(
        parsed.payload.iter().any(|&byte| byte != 0xD5),
        "transcoded G.711a carries non-silence audio"
    );

    // B → engine(far): G.711a in; A receives re-encoded AMR-WB (PT 96).
    let from_b = g711_rtp(8, 200, 0x0B0B_0B0B, 0x55);
    phone_b.send_to(&from_b, far_addr).await.expect("b send");
    let (back, from) = recv(&phone_a).await;
    assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&back).expect("parse");
    assert_eq!(parsed.payload_type, 96, "A receives AMR-WB (PT 96)");
    assert!(!parsed.payload.is_empty(), "AMR-WB egress carries a frame");

    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "volte-pstn".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
}

/// One 20 ms µ-law RTP packet carrying `pcm` (160 samples at 8 kHz).
fn ulaw_rtp_pcm(sequence: u16, ssrc: u32, pcm: &[i16]) -> Vec<u8> {
    use siphon_rtp_codec::Encoder;
    let mut encoder = siphon_rtp_codec::g711::G711::ulaw();
    let mut payload = [0u8; 160];
    let written = encoder.encode(pcm, &mut payload).expect("µ-law encode");
    let mut packet = vec![0x80, 0u8];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&payload[..written]);
    packet
}

/// 8 kHz PCM in 20 ms frames: silence, a record tone, then silence.
fn record_tone_frames(
    silence_before_ms: u32,
    frequency_hz: f32,
    tone_ms: u32,
    silence_after_ms: u32,
) -> Vec<Vec<i16>> {
    let samples = |milliseconds: u32| (8_000u32 * milliseconds / 1000) as usize;
    let mut pcm = vec![0i16; samples(silence_before_ms)];
    let step = 2.0 * std::f32::consts::PI * frequency_hz / 8_000.0;
    let mut phase = 0.0f32;
    for _ in 0..samples(tone_ms) {
        pcm.push((8000.0 * phase.sin()) as i16);
        phase += step;
    }
    pcm.extend(std::iter::repeat_n(0i16, samples(silence_after_ms)));
    pcm.chunks(160).map(<[i16]>::to_vec).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn beep_detection_promotes_a_same_codec_call_and_reports_the_tone_to_the_controller() {
    // The whole feature, end to end through the control plane: a *same-codec plaintext* call that
    // would otherwise relay in-kernel is promoted to the userspace media pipeline purely because
    // `beep_detection` is set (that is `resolve_pipeline`'s new arm), the answering party plays a
    // record tone, and the controller receives one `Event::BeepDetected` naming that leg.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    // A short cadence guard keeps the fixture to ~1.5 s of audio; the guard's own default is
    // exercised by the dsp corpus and the media-pipeline cadence test.
    let profile = ProfileFlags {
        beep_detection: true,
        beep_cadence_guard_ms: Some(320),
        ..Default::default()
    };

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "beep-e2e".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: profile.clone(),
            },
        )
        .await;
    let far_addr = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;

    // Both legs answer PCMU — same codec, so nothing but the flag can force the slow path.
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "beep-e2e".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile,
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    assert!(
        engine.media().is_media_call("beep-e2e"),
        "beep detection must promote a same-codec call off the in-kernel relay"
    );

    // B plays a 1400 Hz / 400 ms record tone. Drain A's socket in lock-step so the relay never
    // backs up behind an unread receive buffer.
    for (sequence, frame) in record_tone_frames(200, 1400.0, 400, 900)
        .into_iter()
        .enumerate()
    {
        phone_b
            .send_to(
                &ulaw_rtp_pcm(sequence as u16, 0x0B0B_0B0B, &frame),
                far_addr,
            )
            .await
            .expect("b send");
        let (_relayed, from) = recv(&phone_a).await;
        assert_eq!(from, near_addr, "the call still relays B's audio to A");
    }

    // The controller's event channel carries exactly the beep, naming B's leg.
    let mut detected = None;
    while let Ok(Ok(event)) = timeout(Duration::from_millis(500), events.recv_async()).await {
        if let Event::BeepDetected {
            call_id,
            from_tag,
            to_tag,
            frequency_hz,
            duration_ms,
            offset_ms,
        } = event
        {
            assert_eq!(call_id, "beep-e2e");
            assert_eq!(from_tag, "tag-b", "the leg that played the tone");
            assert_eq!(to_tag.as_deref(), Some("tag-a"));
            assert!(
                (frequency_hz - 1400.0).abs() < 20.0,
                "reported {frequency_hz} Hz, expected ≈1400"
            );
            assert!(
                duration_ms.abs_diff(400) <= 48,
                "reported {duration_ms} ms, expected ≈400"
            );
            assert!(
                offset_ms.abs_diff(200) <= 48,
                "reported offset {offset_ms} ms"
            );
            detected = Some(());
            break;
        }
    }
    assert!(
        detected.is_some(),
        "the controller must receive a beep_detected event"
    );

    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "beep-e2e".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(
        !engine.media().is_media_call("beep-e2e"),
        "the media actor (and its detector) is torn down with the call"
    );
}

/// An SDP offering several audio codecs in `m=` order, each with an `a=rtpmap` — the shape a real
/// UA sends (a desk phone leading with G.729 and falling back to G.711, say).
fn sdp_codec_list(rtp: SocketAddr, codecs: &[(u8, &str)]) -> String {
    let payload_types: Vec<String> = codecs
        .iter()
        .map(|(payload_type, _)| payload_type.to_string())
        .collect();
    let rtpmaps: String = codecs
        .iter()
        .map(|(payload_type, name)| format!("a=rtpmap:{payload_type} {name}/8000\r\n"))
        .collect();
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {list}\r\n{rtpmaps}a=rtcp-mux\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
        list = payload_types.join(" "),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_relays_when_b_selects_a_codec_a_also_offered() {
    // RFC 3264 §6.1: the answerer picks the format. A leads with G.729 (a codec this engine has no
    // implementation for) but also offers G.711; B answers PCMA. The answer is relayed to A
    // unmodified, so A sends PCMA too and the call is a plain relay — it must NOT be resolved as a
    // G.729→PCMA transcode, which would fail the answer outright on the missing G.729 decoder.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "g729-relay".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_codec_list(addr_a, &[(18, "G729"), (8, "PCMA"), (0, "PCMU")]),
                profile: Default::default(),
            },
        )
        .await;
    let far_addr = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "g729-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(answer, CmdResult::Ok { .. }),
        "the answer is accepted — nothing here needs a G.729 codec, got {answer:?}"
    );
    assert!(
        !engine.media().is_media_call("g729-relay"),
        "no transcoding actor: both parties settled on PCMA, so this is a plain relay"
    );

    // The answer relayed to A advertises B's selection (PCMA), never A's first preference.
    let answer_sdp = ok_sdp_text(&answer);
    let near_addr = sdp::parse(&answer_sdp).expect("answer reply").remote_rtp;
    let m_line = answer_sdp
        .lines()
        .find(|line| line.starts_with("m=audio"))
        .expect("m=audio line");
    assert!(
        m_line.ends_with(" 8"),
        "A is answered with B's selected codec: {m_line}"
    );

    // A's A-law media relays byte-for-byte to B.
    let from_a = g711_rtp(8, 100, 0x0A0A_0A0A, 0xD5);
    phone_a.send_to(&from_a, near_addr).await.expect("a send");
    let (relayed, from) = recv(&phone_b).await;
    assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
    assert_eq!(
        relayed, from_a,
        "relayed verbatim — no decode, no re-encode"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn codec_mask_still_holds_the_near_leg_on_the_masked_codec() {
    // The counterpart to `answer_relays_when_b_selects_a_codec_a_also_offered`: adopting B's
    // selection must not quietly undo `codec-mask`. A offers PCMU and PCMA, the profile masks PCMU
    // so B is offered PCMA alone and answers it. B picking a codec A also offered would normally
    // be a relay, but here it had no other option — the operator asked for A to stay on PCMU and
    // for the engine to transcode, so this stays a media call.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "masked".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    flags: vec!["codec-mask-PCMU".into()],
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "masked".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(answer, CmdResult::Ok { .. }), "got {answer:?}");
    assert!(
        engine.media().is_media_call("masked"),
        "a masked near codec still engages the transcoder"
    );
    // And A is answered with the codec it was held on, not B's (RFC 3264 §6 — A must be told what
    // to send, and what it must send here is what the engine decodes).
    let answer_sdp = ok_sdp_text(&answer);
    let m_line = answer_sdp
        .lines()
        .find(|line| line.starts_with("m=audio"))
        .expect("m=audio line");
    assert!(m_line.ends_with(" 0"), "A is answered with PCMU: {m_line}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_naming_an_unimplemented_codec_says_which_codec_it_is() {
    // The genuine-divergence case on a codec the engine cannot build: A offers only G.723.1,
    // `codec-transcode-PCMA` offers B A-law, and B takes it. That *does* need a G.723.1 decoder
    // the engine does not have, so the answer is refused — and the refusal has to name the
    // codec, not just say "unsupported". G.723.1 rather than G.729, which the `g729` feature
    // now builds in both directions.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "g723-xcode".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 4, "G723"),
                profile: ProfileFlags {
                    flags: vec!["codec-transcode-PCMA".into()],
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "g723-xcode".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let CmdResult::Error { reason } = &answer else {
        panic!("a transcode the engine cannot run is refused, got {answer:?}");
    };
    assert!(
        reason.contains("G.723.1"),
        "the refusal names the codec it could not build: {reason}"
    );
}

#[cfg(feature = "g729")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_g729_leg_transcodes_to_g711_with_the_g729_feature_built_in() {
    // The counterpart to the refusal above, and the reason it had to change codec: the same
    // shape on G.729 now succeeds, because the engine has both directions of it.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "g729-xcode".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 18, "G729"),
                profile: ProfileFlags {
                    flags: vec!["codec-transcode-PCMA".into()],
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "g729-xcode".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(answer, CmdResult::Ok { .. }),
        "a G.729 transcode the engine can run is accepted, got {answer:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reoffer_accepts_a_restated_preference_order_after_a_lower_choice_was_answered() {
    // A offers G.729 first and settles on PCMA. Its re-INVITE restates the same preference order
    // (that is what a re-offer is — RFC 3264 §8), which renegotiates nothing: the call still runs
    // the codec it negotiated, so the re-offer is accepted rather than refused as a codec change.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offered = sdp_codec_list(addr_a, &[(18, "G729"), (8, "PCMA")]);
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "g729-reoffer".into(),
                from_tag: "tag-a".into(),
                sdp: offered.clone(),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "g729-reoffer".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let reoffered = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "g729-reoffer".into(),
                from_tag: "tag-a".into(),
                sdp: offered,
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(reoffered, CmdResult::Ok { .. }),
        "the same list A opened with renegotiates nothing, got {reoffered:?}"
    );

    // Dropping the negotiated codec, though, is a real change the live pipeline cannot absorb.
    let dropped = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "g729-reoffer".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(&dropped, CmdResult::Error { reason } if reason.contains("drops the negotiated codec")),
        "a re-offer without the negotiated codec is refused, got {dropped:?}"
    );
}

#[test]
fn negotiated_near_codec_adopts_the_answered_codec_when_a_offered_it() {
    let pcma = CodecSpec::new(8, "PCMA", 8000, 1, 20);
    let offered = vec![CodecSpec::new(18, "G729", 8000, 1, 20), pcma.clone()];
    let negotiated = negotiated_near_codec(&offered, offered.first().cloned(), Some(&pcma), false)
        .expect("codec");
    assert_eq!(
        negotiated.encoding_name, "PCMA",
        "A follows the answer, not its own first preference"
    );
    assert_eq!(
        negotiated.payload_type, 8,
        "and the answer's payload type, which is what A is told to send"
    );
}

#[test]
fn negotiated_near_codec_keeps_as_own_codec_when_the_answer_diverges() {
    // B selected something A never offered — only a codec policy puts the engine here, and it is
    // exactly the case the transcoder exists for.
    let offered = vec![CodecSpec::new(0, "PCMU", 8000, 1, 20)];
    let g722 = CodecSpec::new(9, "G722", 8000, 1, 20);
    let negotiated = negotiated_near_codec(&offered, offered.first().cloned(), Some(&g722), false)
        .expect("codec");
    assert_eq!(negotiated.encoding_name, "PCMU", "A keeps its own codec");
}

#[test]
fn negotiated_near_codec_keeps_the_primary_without_an_answer_or_an_offer_set() {
    let pcmu = CodecSpec::new(0, "PCMU", 8000, 1, 20);
    assert_eq!(
        negotiated_near_codec(std::slice::from_ref(&pcmu), Some(pcmu.clone()), None, false),
        Some(pcmu.clone()),
        "an answer that resolves no codec changes nothing"
    );
    assert_eq!(
        negotiated_near_codec(&[], Some(pcmu.clone()), Some(&pcmu), false),
        Some(pcmu),
        "an empty offered set (a restored call) changes nothing"
    );
}

#[test]
fn negotiated_near_codec_keeps_a_codec_the_policy_withheld_from_the_far_side() {
    // `codec-mask-G722` means "B never sees G.722, A stays on it, transcode". B answering PCMU —
    // which A also offered — is not A moving to PCMU: B was never given the choice.
    let g722 = CodecSpec::new(9, "G722", 8000, 1, 20);
    let pcmu = CodecSpec::new(0, "PCMU", 8000, 1, 20);
    let offered = vec![g722.clone(), pcmu.clone()];
    let negotiated = negotiated_near_codec(&offered, Some(g722), Some(&pcmu), true).expect("codec");
    assert_eq!(
        negotiated.encoding_name, "G722",
        "a masked near codec still engages the transcoder"
    );
}

#[test]
fn same_codec_compares_the_encoding_not_the_payload_type() {
    // The two sides of a call may number the same codec differently; a differing number is not a
    // transcode. A differing clock rate or channel count is.
    let dynamic = CodecSpec::new(96, "AMR-WB", 16000, 1, 20);
    let other_number = CodecSpec::new(97, "amr-wb", 16000, 1, 20);
    assert!(same_codec(&dynamic, &other_number));
    assert!(!same_codec(
        &CodecSpec::new(0, "L16", 8000, 1, 20),
        &CodecSpec::new(0, "L16", 16000, 1, 20)
    ));
    assert!(!same_codec(
        &CodecSpec::new(0, "L16", 16000, 1, 20),
        &CodecSpec::new(0, "L16", 16000, 2, 20)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_transcodes_ulaw_to_alaw_end_to_end() {
    // A offers PCMU (µ-law) and nothing else; `codec-transcode-PCMA` puts A-law in the offer B
    // sees, and B answers with it. That is a genuine divergence — B selected a codec A never
    // offered — so the two legs resolve to the media slow path, which redirects both to a
    // transcoding actor. Proven end-to-end through the control plane with the redirect dispatcher
    // live. (Had A itself offered PCMA, B's answer would be relayed and no transcode is needed —
    // `answer_relays_when_b_selects_a_codec_a_also_offered` covers that.)
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    // A's offer advertises PCMU and only PCMU; the profile adds PCMA to what B is offered.
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "xcode-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: ProfileFlags {
                    flags: vec!["codec-transcode-PCMA".into()],
                    ..Default::default()
                },
            },
        )
        .await;
    let far_addr = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;

    // B answers PCMA only → near=PCMU (A offered no PCMA), far=PCMA → transcode.
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "xcode-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;

    // A → engine(near) → transcode → B receives A-law (PT 8), not the original µ-law.
    let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
    phone_a.send_to(&from_a, near_addr).await.expect("a send");
    let (transcoded, from) = recv(&phone_b).await;
    assert_eq!(from, far_addr, "media leaves the engine's B-facing port");
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&transcoded).expect("parse");
    assert_eq!(parsed.payload_type, 8, "B receives A-law (PT 8)");
    assert_eq!(parsed.payload.len(), 160);
    assert_ne!(
        parsed.payload,
        &from_a[12..],
        "payload genuinely transcoded"
    );

    // B → engine(far) → transcode → A receives µ-law (PT 0).
    let from_b = g711_rtp(8, 200, 0x0B0B_0B0B, 0x55);
    phone_b.send_to(&from_b, far_addr).await.expect("b send");
    let (back, from) = recv(&phone_a).await;
    assert_eq!(from, near_addr, "media leaves the engine's A-facing port");
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&back).expect("parse");
    assert_eq!(parsed.payload_type, 0, "A receives µ-law (PT 0)");

    // The call is a media-processing call; block then unblock via the control plane.
    assert!(engine.media().is_media_call("xcode-1"));
    let blocked = engine
        .handle(
            CLIENT,
            Command::BlockMedia {
                call_id: "xcode-1".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(matches!(blocked, CmdResult::Ok { .. }));

    // Teardown frees the media actor and routes.
    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "xcode-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(
        !engine.media().is_media_call("xcode-1"),
        "media call deregistered"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn final_quality_reports_per_direction_ingress_stats_for_the_cdr() {
    // A transcode call accumulates RFC 3550 reception stats per direction; the engine reads them
    // back over the actor mailbox (`MediaControl::Report`) at teardown to build the CDR. Prove that
    // round-trip: after A sends media, the actor's `a_to_b` snapshot shows the received packets and
    // A's SSRC, while the silent `b_to_a` direction shows nothing.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "cdr-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "cdr-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;

    // A sends three consecutive frames; awaiting each transcoded output guarantees the actor has
    // processed (and counted) the ingress packet before the next.
    const A_SSRC: u32 = 0x0A0A_0A0A;
    for sequence in 0..3u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, A_SSRC, 0xFF), near_addr)
            .await
            .expect("a send");
        let _ = recv(&phone_b).await;
    }

    let quality = engine
        .media()
        .final_quality("cdr-1", std::time::Duration::from_secs(1))
        .await
        .expect("the actor answers the quality query");
    assert_eq!(
        quality.a_to_b.ssrc,
        Some(A_SSRC),
        "A's stream SSRC is captured for the CDR"
    );
    assert!(
        quality.a_to_b.packets_received >= 3,
        "A's received frames are counted, got {}",
        quality.a_to_b.packets_received
    );
    assert_eq!(
        quality.b_to_a.packets_received, 0,
        "B never sent ⇒ nothing received on the reverse direction"
    );
    // No ~5 s periodic quality tick elapses within the test, so no MOS sample is folded yet — the
    // CDR then renders `mos_avg=-` for this leg (honest: nothing measured), not a fabricated value.
    assert_eq!(
        quality.a_to_b.mos_samples, 0,
        "no periodic MOS sample within the test window"
    );

    // The query is non-destructive: the call still tears down cleanly afterwards.
    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "cdr-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(!engine.media().is_media_call("cdr-1"), "call deregistered");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finish_call_emits_a_call_summary_event_for_the_cdr() {
    // Teardown pushes an `Event::CallSummary` (the structured twin of the cdr log block) to the
    // owner's event sink. A plain relay (both PCMU) has no media actor, so the summary is
    // counters-only — the common case, and it proves the emit path without needing live media.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "sum-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "sum-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "sum-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));

    let mut summary = None;
    while let Ok(event) = events.try_recv() {
        if let Event::CallSummary {
            call_id,
            reason,
            legs,
            started_at_unix_ms,
            ended_at_unix_ms,
            ..
        } = event
        {
            summary = Some((call_id, reason, legs, started_at_unix_ms, ended_at_unix_ms));
        }
    }
    let (call_id, reason, legs, started_at, ended_at) =
        summary.expect("CallSummary emitted on delete");
    assert_eq!(call_id, "sum-1");
    assert_eq!(reason, "delete");
    assert_eq!(legs.len(), 2, "near + far legs");
    assert_eq!(legs[0].tag, "tag-a", "near leg is the offerer");
    assert_eq!(legs[1].tag, "tag-b", "far leg is the answerer");
    assert!(
        legs[0].mos_average.is_none(),
        "a plain relay has no media actor ⇒ counters-only, no MOS"
    );

    // What an RFC 6035 report needs beyond the counters: the wall-clock span, and each leg's
    // addressing. No media flowed, so the parties' addresses are the signalled ones, and a plain relay
    // has no media actor to have originated a stream under an SSRC of its own.
    let started_at = started_at.expect("a wall-clock start");
    let ended_at = ended_at.expect("a wall-clock end");
    assert!(ended_at >= started_at, "the call ends after it starts");
    assert_eq!(legs[0].remote_address, Some(addr_a));
    assert_eq!(legs[1].remote_address, Some(addr_b));
    assert!(
        legs[0]
            .local_address
            .is_some_and(|address| address.port() != 0),
        "the engine's near-leg media address"
    );
    assert_eq!(legs[0].egress_ssrc, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn siprec_subscribe_forks_leg_a_to_an_srs_then_unsubscribe_and_delete() {
    // SIPREC end-to-end (RFC 7866): a transcoding media call, then subscribe_request offers leg
    // A's media to a Session Recording Server, subscribe_answer points the fork at the SRS, A's
    // RTP is forked there, unsubscribe stops it, and delete tears the call (and subscription) down.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let (srs, srs_addr) = phone().await; // the Session Recording Server's media socket

    // A offers PCMU, B answers PCMA → a transcoding media call (so there is decoded PCM to fork).
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    assert!(engine.media().is_media_call("siprec-1"));

    // subscribe_request: the engine offers leg A's media to the SRS and returns an SDP offer + a
    // subscription to-tag. Leg A's negotiated codec is PCMU (PT 0).
    let subscribe = engine
        .handle(
            CLIENT,
            Command::SubscribeRequest {
                call_id: "siprec-1".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            },
        )
        .await;
    let (offer_sdp, subscription_tag) = match subscribe {
        CmdResult::Ok {
            sdp: Some(sdp),
            to_tag: Some(to_tag),
            ..
        } => (sdp, to_tag),
        other => panic!("expected an SDP offer + to_tag, got {other:?}"),
    };
    let offer_info = sdp::parse(&offer_sdp).expect("parse subscriber offer");
    assert_eq!(
        offer_info.primary_codec().expect("codec").encoding_name,
        "PCMU"
    );
    assert!(
        offer_sdp.contains("a=sendonly"),
        "subscriber stream is send-only (RFC 3264)"
    );

    // subscribe_answer: the SRS answers with its own media address. The fork attaches to leg A.
    let srs_answer_sdp = sdp_single_codec(srs_addr, 0, "PCMU");
    let answered = engine
        .handle(
            CLIENT,
            Command::SubscribeAnswer {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag.clone(),
                sdp: srs_answer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(answered, CmdResult::Ok { .. }),
        "subscribe_answer ok: {answered:?}"
    );

    // A sends µ-law RTP through the engine; B gets the A-law transcode AND the SRS gets leg A's
    // RAW ingress RTP byte-for-byte (the raw tee, not a re-encode): same SSRC, sequence, payload.
    let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
    phone_a.send_to(&from_a, near_addr).await.expect("a send");
    let (to_b, _) = recv(&phone_b).await; // the normal transcoded leg is undisturbed
    let (forked, from) = recv(&srs).await;
    assert_eq!(
        from, offer_info.remote_rtp,
        "fork leaves the engine's subscriber port"
    );
    assert_eq!(
        forked, from_a,
        "SRS receives leg A's ORIGINAL RTP byte-for-byte (raw tee)"
    );
    assert_ne!(
        to_b, from_a,
        "B still gets the genuinely transcoded A-law stream"
    );

    // unsubscribe: the fork stops; A's media still transcodes to B.
    let unsubscribed = engine
        .handle(
            CLIENT,
            Command::Unsubscribe {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag,
            },
        )
        .await;
    assert!(matches!(unsubscribed, CmdResult::Ok { .. }));

    // Drain any already-in-flight forked packets, then prove no more arrive after unsubscribe.
    let mut drain = [0u8; 2048];
    while srs.try_recv_from(&mut drain).is_ok() {}
    phone_a
        .send_to(&g711_rtp(0, 101, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let (_to_b_again, _) = recv(&phone_b).await; // B still receives transcoded media
    let mut scratch = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(200), srs.recv_from(&mut scratch))
            .await
            .is_err(),
        "no more forked packets reach the SRS after unsubscribe"
    );

    // delete: tears the call down cleanly (the subscription is already gone).
    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "siprec-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(
        !engine.media().is_media_call("siprec-1"),
        "media call deregistered"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn siprec_subscription_is_freed_when_the_parent_call_is_deleted() {
    // A subscription left open at delete must be torn down with the call (raw tees detached,
    // subscriber port freed) — no orphaned task or leaked endpoint.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let (_srs, srs_addr) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "siprec-2".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "siprec-2".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let subscribe = engine
        .handle(
            CLIENT,
            Command::SubscribeRequest {
                call_id: "siprec-2".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            },
        )
        .await;
    let subscription_tag = match subscribe {
        CmdResult::Ok {
            to_tag: Some(to_tag),
            ..
        } => to_tag,
        other => panic!("expected a to_tag, got {other:?}"),
    };
    engine
        .handle(
            CLIENT,
            Command::SubscribeAnswer {
                call_id: "siprec-2".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag,
                sdp: sdp_single_codec(srs_addr, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;

    // Delete the call without unsubscribing first: teardown must drain the subscription too.
    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "siprec-2".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert_eq!(
        engine.session_count(),
        0,
        "the call drained from the registry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn siprec_subscribe_forks_a_plain_passthrough_relay_to_an_srs() {
    // The headline: SIPREC on a PLAIN G.711 RELAY (same codec both sides → Passthrough, the
    // in-kernel Forward fast path). subscribe_request promotes the relay to userspace, the raw tee
    // copies leg A's ORIGINAL RTP to the SRS byte-for-byte (no re-encode), AND the original peer B
    // keeps receiving the relayed RTP. Then unsubscribe stops the SRS feed (B still flows) and
    // demotes back to the kernel path; delete tears it down.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let (srs, srs_addr) = phone().await;

    // A offers PCMU, B answers PCMU → same codec → a plain Passthrough relay (no media actor).
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let far_addr = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    assert!(
        !engine.media().is_media_call("siprec-relay"),
        "a plain relay has no media actor"
    );

    // subscribe_request: the engine offers leg A's media + promotes the relay to userspace.
    let subscribe = engine
        .handle(
            CLIENT,
            Command::SubscribeRequest {
                call_id: "siprec-relay".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            },
        )
        .await;
    let (offer_sdp, subscription_tag) = match subscribe {
        CmdResult::Ok {
            sdp: Some(sdp),
            to_tag: Some(to_tag),
            ..
        } => (sdp, to_tag),
        other => panic!("expected an SDP offer + to_tag, got {other:?}"),
    };
    let offer_info = sdp::parse(&offer_sdp).expect("parse subscriber offer");
    assert_eq!(
        offer_info.primary_codec().expect("codec").encoding_name,
        "PCMU",
        "offer advertises the source leg's actual codec (RFC 4566)"
    );
    assert!(
        offer_sdp.contains("a=sendonly"),
        "subscriber stream is send-only (RFC 3264)"
    );
    assert!(
        engine.media().is_relay_call("siprec-relay"),
        "the relay was promoted to userspace"
    );

    // subscribe_answer: the SRS answers with its media address; the raw tee attaches to leg A.
    let answered = engine
        .handle(
            CLIENT,
            Command::SubscribeAnswer {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag.clone(),
                sdp: sdp_single_codec(srs_addr, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(answered, CmdResult::Ok { .. }),
        "subscribe_answer ok: {answered:?}"
    );

    // A sends RTP: (1) B still receives the relayed RTP, (2) the SRS receives the byte-identical
    // original RTP (raw tee, not re-encoded).
    let from_a = g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF);
    phone_a.send_to(&from_a, near_addr).await.expect("a send");
    let (to_b, from_b_engine) = recv(&phone_b).await;
    assert_eq!(
        from_b_engine, far_addr,
        "B's media leaves the engine's far port"
    );
    assert_eq!(to_b, from_a, "B still receives the relayed RTP verbatim");
    let (forked, from) = recv(&srs).await;
    assert_eq!(
        from, offer_info.remote_rtp,
        "tee leaves the engine's subscriber port"
    );
    assert_eq!(
        forked, from_a,
        "SRS receives leg A's ORIGINAL RTP byte-for-byte (raw tee)"
    );

    // unsubscribe: the SRS feed stops; B still flows; the call demotes back to the kernel path.
    let unsubscribed = engine
        .handle(
            CLIENT,
            Command::Unsubscribe {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag,
            },
        )
        .await;
    assert!(matches!(unsubscribed, CmdResult::Ok { .. }));
    assert!(
        !engine.media().is_media_call("siprec-relay"),
        "demoted: no media actor remains"
    );

    let mut drain = [0u8; 2048];
    while srs.try_recv_from(&mut drain).is_ok() {}
    phone_a
        .send_to(&g711_rtp(0, 101, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let (to_b_again, _) = recv(&phone_b).await; // B still relays after demotion
    assert_eq!(
        to_b_again,
        g711_rtp(0, 101, 0x0A0A_0A0A, 0xFF),
        "B keeps relaying post-demote"
    );
    let mut scratch = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(200), srs.recv_from(&mut scratch))
            .await
            .is_err(),
        "no more tee'd packets reach the SRS after unsubscribe"
    );

    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "siprec-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert_eq!(
        engine.session_count(),
        0,
        "the call drained from the registry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscribe_request_rejects_a_secure_call() {
    // SIPREC on an SRTP-bridge leg is not supported (the wire bytes are ciphertext, not the leg's
    // clear codec) — subscribe_request must reject it clearly rather than tee garbage.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        ..Default::default()
    };
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "savp-siprec".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile,
            },
        )
        .await;
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "savp-siprec".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_answer_sdp(addr_b, &b_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;

    let result = engine
        .handle(
            CLIENT,
            Command::SubscribeRequest {
                call_id: "savp-siprec".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(result, CmdResult::Error { .. }),
        "SIPREC on a secure call is rejected"
    );
}

/// A µ-law (PCMU, PT 0) RTP packet: a 160-sample / 20 ms frame carrying `payload_byte`.
fn ulaw_rtp_packet(sequence: u16, ssrc: u32, payload_byte: u8) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(&[payload_byte; 160]);
    packet
}

/// The µ-law byte a constant-`level` PCM sample encodes to, so a test can fill a frame with a
/// known energy without hand-computing the G.711 companding table.
fn ulaw_byte(level: i16) -> u8 {
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_codec::Encoder as _;
    let mut encoded = [0u8; 1];
    G711::ulaw()
        .encode(&[level], &mut encoded)
        .expect("one sample encodes to one byte");
    encoded[0]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_attaches_leg_a_to_a_websocket_server_end_to_end() {
    // The mod_audio_stream headline: a control client sets `ws_uri`, the engine dials that WS
    // server and bridges leg A's audio to it. Driven end-to-end through the control plane with the
    // redirect dispatcher live; proves the start handshake, the uplink, the downlink, and teardown.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use futures_util::{SinkExt, StreamExt};
    use siphon_rtp_media::bridge::pcm_to_l16_le;
    use siphon_rtp_media::bridge::protocol::ControlMessage;
    use tokio_tungstenite::tungstenite::Message;

    // Stand up a local WebSocket server: it relays each received frame out `ws_rx`, and forwards a
    // downlink frame requested via `down_tx` into the socket toward the engine.
    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let ws_addr = ws_listener.local_addr().expect("ws addr");
    let (ws_tx, ws_rx) = flume::unbounded::<Message>();
    let (down_tx, down_rx) = flume::unbounded::<Vec<u8>>();
    tokio::spawn(async move {
        let (stream, _) = ws_listener.accept().await.expect("accept ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("ws handshake");
        let (mut sink, mut source) = socket.split();
        loop {
            tokio::select! {
                incoming = source.next() => match incoming {
                    Some(Ok(message)) => {
                        if ws_tx.send(message).is_err() {
                            break;
                        }
                    }
                    _ => break,
                },
                downlink = down_rx.recv_async() => match downlink {
                    Ok(bytes) => {
                        if sink.send(Message::binary(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
    });

    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;

    // A offers PCMU with `ws_uri` set → the engine dials the WS and bridges leg A to it.
    let profile = ProfileFlags {
        ws_uri: Some(format!("ws://{ws_addr}/stream")),
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile,
            },
        )
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "ws offer succeeds");
    assert!(
        engine.ws().is_ws_call("ws-1"),
        "the call is a WS-bridge call"
    );

    // An answer (B answers PCMU too) returns the engine's A-facing endpoint without wiring A↔B.
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ws-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;

    // 1. The WS server receives a `start` text frame first (the mod_audio_stream handshake).
    let first = timeout(Duration::from_secs(3), ws_rx.recv_async())
        .await
        .expect("no timeout")
        .expect("a frame");
    match first {
        Message::Text(text) => assert!(
            matches!(
                ControlMessage::from_json(text.as_str()),
                Ok(ControlMessage::Start(_))
            ),
            "first WS frame is `start`"
        ),
        other => panic!("expected start text frame, got {other:?}"),
    }

    // 2. Uplink: phone A sends µ-law RTP to the engine's A-facing port; the WS server gets an L16
    //    binary uplink frame (8 kHz / 20 ms = 320 bytes).
    phone_a
        .send_to(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let mut got_uplink = false;
    for _ in 0..30 {
        let frame = timeout(Duration::from_secs(2), ws_rx.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        if let Message::Binary(bytes) = frame {
            assert_eq!(bytes.len(), 320, "8k/20ms L16 uplink");
            got_uplink = true;
            break;
        }
    }
    assert!(got_uplink, "expected an uplink L16 binary frame on the WS");

    // 3. Downlink: the WS server sends a binary L16 frame; phone A receives an RTP packet (the
    //    bridge encodes it in A's codec and the drain task sends it toward A).
    let mut l16 = [0u8; 320];
    pcm_to_l16_le(&[2000i16; 160], &mut l16);
    down_tx.send(l16.to_vec()).expect("queue downlink");
    let mut got_downlink = false;
    for _ in 0..30 {
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
        {
            let packet =
                siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse rtp");
            assert_eq!(
                packet.payload_type, 0,
                "downlink encoded in A's codec (µ-law)"
            );
            assert_eq!(packet.payload.len(), 160, "8k/20ms µ-law frame");
            got_downlink = true;
            break;
        }
    }
    assert!(
        got_downlink,
        "expected a downlink RTP packet toward phone A"
    );

    // 4. Teardown: delete frees the WS bridge (route + tasks).
    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "ws-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(
        !engine.ws().is_ws_call("ws-1"),
        "WS call deregistered on delete"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_attaches_the_single_leg_to_a_websocket_server_end_to_end() {
    // The "AI answers the call" shape: a single-leg UAS answer (`answer_local`) with `ws_uri` set
    // must dial the WS server and make it the caller's far side — the same takeover `offer` does,
    // on the verb the voice-AI path actually uses. This previously answered `ok` with a valid SDP
    // and never dialled at all, falling back to the local echo pipeline: RTP flowed both ways, so
    // a naive end-to-end check passed while the audio never went near the configured server. The
    // assertion that catches that is on the *server* side (a `start` frame arrives), not on RTP.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use futures_util::{SinkExt, StreamExt};
    use siphon_rtp_media::bridge::pcm_to_l16_le;
    use siphon_rtp_media::bridge::protocol::ControlMessage;
    use tokio_tungstenite::tungstenite::Message;

    // Same local WS server harness as the offer test: relay every received frame out `ws_rx`, and
    // push a downlink frame requested via `down_tx` into the socket toward the engine.
    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let ws_addr = ws_listener.local_addr().expect("ws addr");
    let (ws_tx, ws_rx) = flume::unbounded::<Message>();
    let (down_tx, down_rx) = flume::unbounded::<Vec<u8>>();
    tokio::spawn(async move {
        let (stream, _) = ws_listener.accept().await.expect("accept ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("ws handshake");
        let (mut sink, mut source) = socket.split();
        loop {
            tokio::select! {
                incoming = source.next() => match incoming {
                    Some(Ok(message)) => {
                        if ws_tx.send(message).is_err() {
                            break;
                        }
                    }
                    _ => break,
                },
                downlink = down_rx.recv_async() => match downlink {
                    Ok(bytes) => {
                        if sink.send(Message::binary(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
    });

    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;

    // The caller offers PCMU; the controller answers locally with `ws_uri` set.
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-ws".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(format!("ws://{ws_addr}/stream")),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = ok_sdp_text(&result);
    assert!(
        engine.ws().is_ws_call("al-ws"),
        "answer_local with ws_uri must register a WS-bridge call"
    );
    // The takeover owns the leg, so no local processing pipeline is promoted alongside it.
    assert!(
        !engine.media().is_transcoding_call("al-ws"),
        "a WS takeover must not also promote a local media pipeline"
    );
    {
        let call = engine.calls.get("al-ws").expect("call present");
        assert_eq!(call.pipeline, PipelineKind::Ws);
        assert_eq!(
            call.near_codec
                .as_ref()
                .expect("ingress codec")
                .encoding_name,
            "PCMU"
        );
        assert!(
            call.far_codec.is_none(),
            "the WS server is the far side — there is no far RTP codec to claim"
        );
    }

    // The caller sends to (and is reflected from) the address this answer advertises.
    let caller_target = sdp::parse(&answer).expect("answer sdp").remote_rtp;

    // 1. The `start` handshake reaches the server, carrying the same MediaFormat shape `offer` emits.
    let first = timeout(Duration::from_secs(3), ws_rx.recv_async())
        .await
        .expect("no timeout")
        .expect("a frame");
    match first {
        Message::Text(text) => match ControlMessage::from_json(text.as_str()) {
            Ok(ControlMessage::Start(start)) => {
                assert_eq!(start.media.sample_rate, 8000, "PCMU decodes to 8 kHz L16");
                assert_eq!(start.media.channels, 1);
                assert_eq!(start.media.bit_depth, 16);
                assert_eq!(start.media.ptime, 20);
            }
            other => panic!("first WS frame must be `start`, got {other:?}"),
        },
        other => panic!("expected start text frame, got {other:?}"),
    }

    // 2. Uplink: the caller's µ-law RTP arrives at the server as one 20 ms L16 frame (320 bytes).
    phone_a
        .send_to(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), caller_target)
        .await
        .expect("a send");
    let mut got_uplink = false;
    for _ in 0..30 {
        let frame = timeout(Duration::from_secs(2), ws_rx.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        if let Message::Binary(bytes) = frame {
            assert_eq!(bytes.len(), 320, "8k/20ms L16 uplink");
            got_uplink = true;
            break;
        }
    }
    assert!(got_uplink, "expected an uplink L16 binary frame on the WS");

    // 3. Downlink: server PCM is encoded in the codec the single-leg answer picked and reaches the
    //    caller as RTP (the proof a caller hears the echoing server, not the engine's own echo).
    let mut l16 = [0u8; 320];
    pcm_to_l16_le(&[2000i16; 160], &mut l16);
    down_tx.send(l16.to_vec()).expect("queue downlink");
    let mut got_downlink = false;
    for _ in 0..30 {
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
        {
            let packet =
                siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse rtp");
            assert_eq!(
                packet.payload_type, 0,
                "downlink encoded in the answered codec"
            );
            assert_eq!(packet.payload.len(), 160, "8k/20ms µ-law frame");
            got_downlink = true;
            break;
        }
    }
    assert!(
        got_downlink,
        "expected a downlink RTP packet toward the caller"
    );

    // 4. Teardown: delete closes the WS stream and drains the registry.
    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "al-ws".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(
        !engine.ws().is_ws_call("al-ws"),
        "WS call deregistered on delete"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_ws_stream_ends_when_the_call_is_reaped_as_idle() {
    // `delete` is not the only way a takeover call ends: a caller that goes silent is reaped by
    // the media-timeout sweeper, and the WS stream must end with it rather than leaving the server
    // holding an open socket for a call that no longer exists. Both paths run through
    // `finish_call`, so this pins the sweeper half the `delete` test does not reach.
    use futures_util::StreamExt;

    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let ws_addr = ws_listener.local_addr().expect("ws addr");
    // Signals once the server's read loop ends — i.e. the engine closed the connection.
    let (closed_tx, closed_rx) = flume::unbounded::<()>();
    tokio::spawn(async move {
        let (stream, _) = ws_listener.accept().await.expect("accept ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("ws handshake");
        let (_sink, mut source) = socket.split();
        while let Some(Ok(_)) = source.next().await {}
        let _ = closed_tx.send(());
    });

    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-ws-reap".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(format!("ws://{ws_addr}/stream")),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(matches!(result, CmdResult::Ok { .. }));
    assert!(engine.ws().is_ws_call("al-ws-reap"));

    // The caller never sends a packet, so the leg is idle from creation and the sweeper takes it.
    engine.datapath().advance_clock(10);
    assert_eq!(engine.reap_idle(5, 0).await, vec!["al-ws-reap".to_string()]);
    assert!(
        !engine.ws().is_ws_call("al-ws-reap"),
        "the reaped call's WS bridge is deregistered"
    );
    // …and the server actually sees the stream end, not just our registry forgetting about it.
    timeout(Duration::from_secs(3), closed_rx.recv_async())
        .await
        .expect("the WS server must observe the stream closing")
        .expect("close signal");
}

#[tokio::test]
async fn answer_local_with_an_unreachable_ws_uri_fails_the_command() {
    // A takeover that cannot be stood up must NOT answer `ok`. Answering success with no bridge
    // attached is the defect this path had in its worst form: the controller connects a caller to
    // nothing and has no way to detect it. Fail like `no-encodable-codec` so it can render a real
    // SIP failure — and leave nothing behind (ports + quota freed).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;

    // Bind a port and drop the listener to get an address nothing is listening on.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let dead_addr = dead.local_addr().expect("addr");
    drop(dead);

    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-ws-dead".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(format!("ws://{dead_addr}/stream")),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(
        matches!(result, CmdResult::Error { .. }),
        "an unreachable ws_uri must fail the command, not answer ok: {result:?}"
    );
    assert!(
        !engine.calls.contains_key("al-ws-dead"),
        "the half-built call is torn back down"
    );
    assert!(!engine.ws().is_ws_call("al-ws-dead"));
    assert_eq!(
        engine.client_call_count(CLIENT),
        0,
        "the quota slot is released"
    );
}

// ----------------------------------------------------------------------------------------
// WebSocket takeover on a SECURE offerer (SDES-SRTP / DTLS-SRTP).
//
// A takeover call deliberately wires no A<->B path: the WS server *is* leg A's far side. That is
// only a complete call when the engine can actually terminate leg A's media — which, on a secure
// offerer, means holding a `SecureLeg` (RFC 3711) keyed by SDES (RFC 4568) or by the DTLS-SRTP
// handshake (RFC 5764). Accepting `ws_uri` on a secure offerer without one answers cleanly and
// bridges nothing: A's SRTP is fed to the decoder as ciphertext and the downlink leaves as
// plaintext RTP the peer discards.
// ----------------------------------------------------------------------------------------

/// An **SDES-SRTP offerer** (RFC 4568): the caller's own `m=audio` is `RTP/SAVP` and carries its
/// `a=crypto`. Distinct from the engine's `transport_protocol` SDES, which secures leg *B*.
fn sdes_offerer_sdp(rtp: SocketAddr, key: &CryptoAttribute) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\na={crypto}\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
        crypto = key.to_attribute_value(),
    )
}

/// A **DTLS-SRTP offerer** (RFC 5764 / RFC 5763 §5): the caller's own `m=audio` is
/// `UDP/TLS/RTP/SAVPF` and carries `a=setup` + `a=fingerprint`.
fn dtls_offerer_sdp(
    rtp: SocketAddr,
    fingerprint: &siphon_rtp_dtls::Fingerprint,
    setup: &str,
) -> String {
    let hex = fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
             a=setup:{setup}\r\na=fingerprint:{hash} {hex}\r\n",
        ip = rtp.ip(),
        port = rtp.port(),
        hash = fingerprint.hash_function,
    )
}

/// A **NATed offerer**: its `c=` carries the address the UA sees on its own interface, which is
/// not one anything can send to, while its media really arrives from — and has to be answered at
/// — somewhere else entirely. `signalled_port` is the media port the UA chose; a cone NAT
/// preserves it and a symmetric one does not, which is the difference the two tests below draw.
fn nated_offer_sdp(private_ip: &str, signalled_port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {private_ip}\r\ns=-\r\nc=IN IP4 {private_ip}\r\nt=0 0\r\n\
             m=audio {signalled_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
    )
}

/// Where `call_id`'s WebSocket takeover bridge is currently sending its downlink.
fn takeover_downlink_target(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> SocketAddr {
    engine
        .ws()
        .route_state(call_id)
        .expect("the call has a takeover route")
        .egress
        .destination()
}

/// A WS server that republishes every frame it receives on `frames` and forwards anything pushed
/// into `downlink` to the engine. The shared harness for the secure-takeover tests.
async fn takeover_ws_server() -> (
    String,
    flume::Receiver<tokio_tungstenite::tungstenite::Message>,
    flume::Sender<Vec<u8>>,
) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let addr = listener.local_addr().expect("ws addr");
    let (frames_tx, frames_rx) = flume::unbounded::<Message>();
    let (down_tx, down_rx) = flume::unbounded::<Vec<u8>>();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("ws handshake");
        let (mut sink, mut source) = socket.split();
        loop {
            tokio::select! {
                incoming = source.next() => match incoming {
                    Some(Ok(message)) => {
                        if frames_tx.send(message).is_err() {
                            break;
                        }
                    }
                    _ => break,
                },
                downlink = down_rx.recv_async() => match downlink {
                    Ok(bytes) => {
                        if sink.send(Message::binary(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
    });
    (format!("ws://{addr}/stream"), frames_rx, down_tx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_with_a_silent_server_still_sends_at_the_ptime_rate() {
    // R6. A takeover leg is the caller's only far side, so its egress rate used to track the
    // bot's duty cycle: nothing at all on a call where the server never spoke. To the caller that
    // is dead air on a line that is plainly still up, and it lets the NAT pinhole toward them
    // expire between turns. The engine wires comfort-idle on for every takeover bridge, so the
    // clock runs whether or not the server has anything to say.
    use crate::srtp_bridge::run_redirect_dispatcher;

    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ws-quiet".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(
        matches!(result, CmdResult::Ok { .. }),
        "the takeover answers"
    );
    expect_ws_start(&frames).await;

    // The server says nothing for the whole test. Collect a run of downlink packets anyway.
    let mut buffer = [0u8; 2048];
    let mut stamps = Vec::new();
    for _ in 0..6 {
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(500), phone_a.recv_from(&mut buffer)).await
        else {
            break;
        };
        let packet = siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("rtp");
        assert_eq!(
            packet.payload_type, 0,
            "on the caller's own negotiated codec"
        );
        assert_eq!(packet.payload.len(), 160, "a full 20 ms frame");
        stamps.push(packet.timestamp);
    }
    assert!(
        stamps.len() >= 4,
        "the leg keeps sending while the server is quiet (got {})",
        stamps.len()
    );
    for pair in stamps.windows(2) {
        assert_eq!(
            pair[1].wrapping_sub(pair[0]),
            160,
            "the egress clock advances one ptime per packet, not per bot utterance"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_carrying_ingress_is_not_reaped_but_a_silent_one_still_is() {
    // R7. The idle sweep reads `Datapath::last_activity`, and the `Redirect` arm deliberately
    // never sets it — each userspace consumer stamps its own, after its own gate, so a spoofed
    // spray cannot hold a dead path open. The takeover pipeline never did, so its endpoint stayed
    // at `created_tick` for the life of the call and the sweep tore it down at the media timeout
    // however much audio was arriving. It presents as the caller hanging up.
    //
    // Both halves matter and are asserted together: a call being talked into must survive, and a
    // call whose caller has genuinely stopped must still be reaped on schedule.
    use crate::srtp_bridge::run_redirect_dispatcher;

    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ws-idle".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    let caller_target = sdp::parse(&ok_sdp_text(&result))
        .expect("answer sdp")
        .remote_rtp;
    expect_ws_start(&frames).await;

    // Move the clock past the timeout *first*, so surviving the sweep can only be the packet
    // below and never a call that is simply too young to reap.
    engine.datapath().advance_clock(10);
    phone_a
        .send_to(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), caller_target)
        .await
        .expect("caller send");
    // The uplink frame is the synchronisation point: it proves the datagram cleared the gate and
    // reached the bridge, which is strictly after the liveness stamp.
    assert!(
        next_uplink_frame(&frames).await.is_some(),
        "the caller's audio reaches the WS server"
    );

    assert!(
        engine.reap_idle(5, 0).await.is_empty(),
        "a takeover call being talked into is not idle"
    );
    assert!(
        engine.ws().is_ws_call("ws-idle"),
        "and its bridge is intact"
    );

    // Now the caller goes quiet: the sweep must still do its job.
    engine.datapath().advance_clock(10);
    assert_eq!(
        engine.reap_idle(5, 0).await,
        vec!["ws-idle".to_string()],
        "a takeover call whose caller has stopped sending is still reaped"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nated_takeover_answers_at_the_received_from_address_not_the_private_one() {
    // The `received-from` hint re-keyed a takeover leg's ingress *gate* and stopped there: the
    // downlink kept the address off the caller's `c=`, which for a NATed UA is one it never
    // receives on. On a relay that costs the pre-latch window, because the datapath's own latch
    // corrects it from the peer's first accepted packet. A takeover leg has no reverse relay
    // direction and so no latch behind it — the wrong address was permanent, and the caller heard
    // nothing at all for the whole call while its own audio arrived and decoded perfectly.
    //
    // The cone-NAT shape: the hint carries the real source address and the NAT preserved the port
    // the UA signalled, so seeding the destination from the hint lands exactly on the caller.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_media::bridge::pcm_to_l16_le;

    let (ws_uri, frames, downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;

    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "nat-takeover".into(),
                from_tag: "tag-a".into(),
                sdp: nated_offer_sdp("192.0.2.9", addr_a.port()),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    // What the SIP proxy observed the request arrive from.
                    received_from: Some(addr_a.ip()),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&result)).expect("answer sdp");
    let caller_target = answer.remote_rtp;

    // Before the caller has sent a single packet — the window the whole defect lived in.
    assert_eq!(
        takeover_downlink_target(&engine, "nat-takeover"),
        addr_a,
        "the downlink is aimed at the observed source, never at the signalled private address"
    );

    // And end to end: the caller's audio reaches the server, and the server's audio reaches the
    // caller. The second half is what a NATed caller never got.
    phone_a
        .send_to(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), caller_target)
        .await
        .expect("caller send");
    assert_eq!(
        next_uplink_frame(&frames)
            .await
            .expect("the WS server received the caller's audio")
            .len(),
        320,
        "8k/20ms L16 uplink"
    );

    let mut l16 = [0u8; 320];
    pcm_to_l16_le(&[2000i16; 160], &mut l16);
    downlink.send(l16.to_vec()).expect("queue downlink");
    let mut buffer = [0u8; 2048];
    let mut heard = None;
    for _ in 0..40 {
        let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
        else {
            continue;
        };
        assert_eq!(
            from, caller_target,
            "the downlink leaves the leg's own socket"
        );
        heard = Some(
            siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len])
                .expect("parse rtp")
                .payload_type,
        );
        break;
    }
    assert_eq!(heard, Some(0), "the caller hears the bot, in its own codec");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_takeover_leg_latches_its_downlink_when_the_signalled_port_is_wrong() {
    // The other half of the fix, and the honest bound on the first. Behind a *symmetric* NAT the
    // public media port need not be the one the UA signalled, so seeding the destination from the
    // `received-from` hint is a better guess, not a guarantee — it fixes the address and can
    // still miss the port. Every other pipeline recovers from that for free, because a relay leg
    // latches its peer's observed source; a takeover leg has no reverse relay direction, so it
    // latches here or not at all.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_media::bridge::pcm_to_l16_le;

    let (ws_uri, frames, downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    // Two real sockets: the port the UA signalled, and the different one its media comes from.
    let (stale_phone, stale_addr) = phone().await;
    let (phone_a, addr_a) = phone().await;
    assert_ne!(addr_a.port(), stale_addr.port());

    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "nat-rebind".into(),
                from_tag: "tag-a".into(),
                sdp: nated_offer_sdp("192.0.2.9", stale_addr.port()),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    received_from: Some(addr_a.ip()),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&result)).expect("answer sdp");
    let caller_target = answer.remote_rtp;
    assert_eq!(
        takeover_downlink_target(&engine, "nat-rebind"),
        stale_addr,
        "the seed pairs the hint's address with the port the UA signalled — right address, \
             wrong port"
    );

    // The caller's media arrives from its real port. It clears the gate (the hint fixed the
    // address, which is all the gate keys on) and must move the downlink onto it.
    phone_a
        .send_to(&ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF), caller_target)
        .await
        .expect("caller send");
    assert_eq!(
        next_uplink_frame(&frames)
            .await
            .expect("the caller's audio reaches the server")
            .len(),
        320
    );
    assert_eq!(
        takeover_downlink_target(&engine, "nat-rebind"),
        addr_a,
        "the leg latched the source its media actually came from"
    );

    let mut l16 = [0u8; 320];
    pcm_to_l16_le(&[2000i16; 160], &mut l16);
    downlink.send(l16.to_vec()).expect("queue downlink");
    let mut buffer = [0u8; 2048];
    let mut heard = false;
    for _ in 0..40 {
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
        else {
            continue;
        };
        assert_eq!(
            siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len])
                .expect("parse rtp")
                .payload_type,
            0
        );
        heard = true;
        break;
    }
    assert!(heard, "the caller hears the bot once the leg has latched");

    // Nothing keeps going to the port the signalling named once the latch has moved.
    let mut stale = [0u8; 2048];
    let after_latch = timeout(
        Duration::from_millis(300),
        stale_phone.recv_from(&mut stale),
    )
    .await;
    assert!(
        after_latch.is_err(),
        "the pre-latch guess is abandoned, not kept alongside the latched address"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_refuses_ws_takeover_on_an_sdes_srtp_offerer() {
    // The two-leg takeover (`offer` + `ws_uri`) builds A's answer at `answer` time out of *B's*
    // SDP, so it has nowhere to advertise the engine's own `a=crypto` — the engine cannot become
    // the secure far side of A on this verb. Accepting it produced a call that answered and
    // bridged nothing. Refuse at OFFER time, before the controller commits to the dialog.
    //
    // The WS server is live, so the refusal is proven to be about the offerer's security posture
    // and not an incidental dial failure.
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let peer_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("peer key");
    let result = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-sdes-offer".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &peer_key),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert!(
            reason.contains("ws-takeover-secure-offerer"),
            "the refusal must name the reason, got: {reason}"
        ),
        other => panic!("a secure offerer with ws_uri must be refused, got {other:?}"),
    }
    assert!(
        !engine.calls.contains_key("ws-sdes-offer"),
        "a refused offer creates no call"
    );
    assert!(!engine.ws().is_ws_call("ws-sdes-offer"));
    assert_eq!(engine.client_call_count(CLIENT), 0, "no quota slot leaked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_refuses_ws_takeover_on_a_dtls_srtp_offerer() {
    // Same gap on the DTLS-SRTP (RFC 5764) shape — a browser-style offerer.
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let peer_cert = siphon_rtp_dtls::DtlsCertificate::generate().expect("peer cert");
    let result = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-dtls-offer".into(),
                from_tag: "tag-a".into(),
                sdp: dtls_offerer_sdp(addr_a, &peer_cert.fingerprint(), "actpass"),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert!(
            reason.contains("ws-takeover-secure-offerer"),
            "the refusal must name the reason, got: {reason}"
        ),
        other => panic!("a DTLS-SRTP offerer with ws_uri must be refused, got {other:?}"),
    }
    assert!(!engine.calls.contains_key("ws-dtls-offer"));
    assert_eq!(engine.client_call_count(CLIENT), 0, "no quota slot leaked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_on_an_sdes_offerer_answers_with_the_engines_own_key() {
    // `answer_local` owns the answer to A outright, so it *can* be A's secure far side: it mints
    // its own SDES key (RFC 4568), answers `RTP/SAVP` + that key, and keys the takeover leg. The
    // key it advertises must be the ENGINE's, never the offerer's echoed back — echoing A's key
    // would have A decrypt our egress with a key we never encrypt under.
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let peer_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("peer key");
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-sdes-ws".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &peer_key),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&result)).expect("answer sdp");
    assert!(answer.secure, "the answer keeps the secure profile");
    let advertised = answer
        .crypto
        .first()
        .copied()
        .expect("the answer carries the engine's own a=crypto");
    assert_ne!(
        advertised.key.to_inline_bytes(),
        peer_key.key.to_inline_bytes(),
        "the engine must advertise its OWN key, not echo the offerer's"
    );
    assert!(engine.ws().is_ws_call("al-sdes-ws"), "the takeover is up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_on_a_dtls_offerer_answers_with_the_engines_own_fingerprint() {
    // RFC 5763 §5: the answer carries the ENGINE's certificate fingerprint and the complement of
    // the offerer's `a=setup` role. Echoing A's own fingerprint back (the pre-change behaviour of
    // the plaintext single-leg path) makes the handshake unverifiable against us.
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let peer_cert = siphon_rtp_dtls::DtlsCertificate::generate().expect("peer cert");
    let peer_fingerprint = peer_cert.fingerprint();
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-dtls-ws".into(),
                from_tag: "tag-a".into(),
                sdp: dtls_offerer_sdp(addr_a, &peer_fingerprint, "active"),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&result)).expect("answer sdp");
    assert!(answer.dtls, "the answer stays UDP/TLS/RTP/SAVPF");
    let advertised = answer.fingerprint.clone().expect("engine a=fingerprint");
    assert_ne!(
        advertised.bytes, peer_fingerprint.bytes,
        "the engine must advertise its OWN fingerprint, not echo the offerer's"
    );
    // The offerer said `active`, so the engine is the DTLS server (RFC 5763 §5).
    assert_eq!(answer.setup, Some(sdp::Setup::Passive), "complement role");
    assert!(engine.ws().is_ws_call("al-dtls-ws"), "the takeover is up");
}

/// Pull WS frames until a binary (L16 uplink) one arrives, or give up. The bridge only emits an
/// uplink frame for a tick that actually had decoded audio (a starved leg emits nothing), so the
/// arrival of one is itself the proof that media crossed the leg.
async fn next_uplink_frame(
    frames: &flume::Receiver<tokio_tungstenite::tungstenite::Message>,
) -> Option<Vec<u8>> {
    use tokio_tungstenite::tungstenite::Message;
    for _ in 0..40 {
        match timeout(Duration::from_secs(2), frames.recv_async()).await {
            Ok(Ok(Message::Binary(bytes))) => return Some(bytes.to_vec()),
            Ok(Ok(_)) => continue,
            _ => return None,
        }
    }
    None
}

/// Consume the WS `start` handshake frame (the first thing every bridge sends), so a later
/// negative assertion about audio is not satisfied by the handshake.
async fn expect_ws_start(frames: &flume::Receiver<tokio_tungstenite::tungstenite::Message>) {
    use siphon_rtp_media::bridge::protocol::ControlMessage;
    use tokio_tungstenite::tungstenite::Message;
    let first = timeout(Duration::from_secs(3), frames.recv_async())
        .await
        .expect("no timeout")
        .expect("a frame");
    match first {
        Message::Text(text) => assert!(
            matches!(
                ControlMessage::from_json(text.as_str()),
                Ok(ControlMessage::Start(_))
            ),
            "first WS frame is `start`"
        ),
        other => panic!("expected the start text frame, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secure_sdes_takeover_decrypts_ingress_and_encrypts_the_downlink() {
    // End to end on an SDES-SRTP (RFC 4568) offerer: the caller's SRTP reaches the WS server as
    // clear L16 PCM, and the server's PCM reaches the caller as SRTP it can actually decrypt with
    // the key the answer advertised. Both halves matter — the pre-change path fed the decoder
    // ciphertext *and* pushed the downlink out in the clear.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_media::bridge::pcm_to_l16_le;

    let (ws_uri, frames, downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let peer_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("peer key");

    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "sdes-takeover".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &peer_key),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&result)).expect("answer sdp");
    let engine_key = answer.crypto.first().copied().expect("engine a=crypto");
    let caller_target = answer.remote_rtp;
    assert_eq!(
        engine.ws().secure_state("sdes-takeover"),
        Some(true),
        "an SDES takeover leg is keyed the moment the answer is written"
    );

    // The caller's own leg: it encrypts with its own key and decrypts with the engine's.
    let mut caller_leg = SecureLeg::new(&peer_key.key, &engine_key.key);

    // Uplink: SRTP in, clear 8 kHz / 20 ms L16 out on the WebSocket.
    let clear = ulaw_rtp_packet(7, 0x0A0A_0A0A, 0xFF);
    let mut sealed = Vec::new();
    caller_leg
        .protect(&clear, &mut sealed)
        .expect("caller SRTP");
    phone_a
        .send_to(&sealed, caller_target)
        .await
        .expect("caller send");
    let uplink = next_uplink_frame(&frames)
        .await
        .expect("the WS server received the decrypted audio");
    assert_eq!(uplink.len(), 320, "8k/20ms L16 uplink");

    // Downlink: the server's PCM comes back to the caller as SRTP, not plaintext RTP.
    let mut l16 = [0u8; 320];
    pcm_to_l16_le(&[2000i16; 160], &mut l16);
    downlink.send(l16.to_vec()).expect("queue downlink");
    let mut buffer = [0u8; 2048];
    let mut decrypted = None;
    for _ in 0..40 {
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
        else {
            continue;
        };
        let datagram = &buffer[..len];
        // 12-byte RTP header + 160-byte µ-law + the RFC 3711 §3.1 auth tag.
        assert_eq!(
            len,
            12 + 160 + 10,
            "the downlink carries an SRTP auth tag, so it is not plaintext RTP"
        );
        let mut clear_out = Vec::new();
        caller_leg
            .unprotect(datagram, &mut clear_out)
            .expect("the caller decrypts the downlink with the advertised key");
        assert_ne!(
            &clear_out[12..],
            &datagram[12..172],
            "the payload really was encrypted on the wire"
        );
        decrypted = Some(clear_out);
        break;
    }
    let decrypted = decrypted.expect("a downlink packet reached the caller");
    let packet = siphon_rtp_media::rtp::RtpPacket::parse(&decrypted).expect("parse rtp");
    assert_eq!(packet.payload_type, 0, "encoded in the caller's codec");
    assert_eq!(packet.payload.len(), 160, "8k/20ms µ-law frame");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_secure_dtls_takeover_emits_nothing_until_the_handshake_keys_it() {
    // End to end on a DTLS-SRTP (RFC 5764) offerer. Two properties, in order:
    //
    // 1. Before the handshake completes the leg is unkeyed, and the bridge's ticker is already
    //    producing downlink frames — so this is exactly the window where a fail-open drain would
    //    spray plaintext RTP at a peer that negotiated SRTP. Nothing may leave.
    // 2. Once the handshake keys it, the caller's SRTP reaches the WS server as clear PCM and the
    //    downlink comes back encrypted under the DTLS-derived key.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_media::bridge::pcm_to_l16_le;

    let (ws_uri, frames, downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let phone_a = Arc::new(
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind a"),
    );
    let addr_a = phone_a.local_addr().expect("addr a");
    let caller_cert = siphon_rtp_dtls::DtlsCertificate::generate().expect("caller cert");

    // The caller offers `a=setup:active`, so the engine answers `passive` and is the DTLS server.
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "dtls-takeover".into(),
                from_tag: "tag-a".into(),
                sdp: dtls_offerer_sdp(addr_a, &caller_cert.fingerprint(), "active"),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&result)).expect("answer sdp");
    let engine_fingerprint = answer.fingerprint.clone().expect("engine fingerprint");
    let caller_target = answer.remote_rtp;
    assert_eq!(
        engine.ws().secure_state("dtls-takeover"),
        Some(false),
        "a DTLS takeover leg starts unkeyed — the handshake has not run yet"
    );

    // 1. Fail-closed. The bridge ticker is running, so a fail-open drain would already be sending.
    let mut l16 = [0u8; 320];
    pcm_to_l16_le(&[2000i16; 160], &mut l16);
    downlink.send(l16.to_vec()).expect("queue early downlink");
    let mut buffer = [0u8; 2048];
    for _ in 0..5 {
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(120), phone_a.recv_from(&mut buffer)).await
        {
            panic!(
                "an unkeyed DTLS takeover leg emitted {len} bytes toward the caller; \
                     a secure leg must drop rather than fall back to plaintext"
            );
        }
    }

    // 2. Drive the caller's side of the handshake (it is the DTLS client).
    let mut caller_leg = peer_dtls_handshake(
        phone_a.clone(),
        addr_a,
        caller_target,
        &caller_cert,
        &engine_fingerprint,
    )
    .await;
    for _ in 0..100 {
        if engine.ws().secure_state("dtls-takeover") == Some(true) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        engine.ws().secure_state("dtls-takeover"),
        Some(true),
        "the handshake keyed the takeover leg"
    );

    // Uplink: the caller's SRTP reaches the WS server as clear PCM.
    let clear = ulaw_rtp_packet(11, 0x0C0C_0C0C, 0xFF);
    let mut sealed = Vec::new();
    caller_leg
        .protect(&clear, &mut sealed)
        .expect("caller SRTP");
    phone_a
        .send_to(&sealed, caller_target)
        .await
        .expect("caller send");
    let uplink = next_uplink_frame(&frames)
        .await
        .expect("the WS server received the decrypted audio");
    assert_eq!(uplink.len(), 320, "8k/20ms L16 uplink");

    // Downlink: encrypted under the DTLS-derived key, and the caller can read it.
    downlink.send(l16.to_vec()).expect("queue downlink");
    let mut decrypted = None;
    for _ in 0..40 {
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
        else {
            continue;
        };
        let mut clear_out = Vec::new();
        if caller_leg.unprotect(&buffer[..len], &mut clear_out).is_ok() {
            assert_eq!(
                len,
                clear_out.len() + 10,
                "the wire packet carries the RFC 3711 auth tag"
            );
            decrypted = Some(clear_out);
            break;
        }
    }
    let decrypted = decrypted.expect("an SRTP downlink packet reached the caller");
    let packet = siphon_rtp_media::rtp::RtpPacket::parse(&decrypted).expect("parse rtp");
    assert_eq!(packet.payload_type, 0, "encoded in the caller's codec");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secure_offerers_key_is_never_forwarded_to_the_callee() {
    // The defect, stated as the test: with no key of its own toward A the engine passed A's
    // `a=crypto` straight through into the offer B receives — handing a third party the offerer's
    // SRTP key — while answering A `RTP/AVP`, i.e. downgrading the caller it had just leaked the
    // key of. Now the engine mints its own key for A, terminates A's SRTP, and B sees plaintext.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let caller_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("caller key");

    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "secure-caller".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &caller_key),
                profile: Default::default(),
            },
        )
        .await;
    let far_offer = ok_sdp_text(&offered);
    assert!(
        !far_offer.contains("a=crypto"),
        "the callee must never be handed the caller's SRTP key: {far_offer}"
    );
    assert!(
        far_offer.contains("RTP/AVP") && !far_offer.contains("SAVP"),
        "and is offered plaintext, since the engine terminates the caller's SRTP: {far_offer}"
    );

    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "secure-caller".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&answered);
    let parsed = sdp::parse(&answer).expect("answer parses");
    assert!(
        parsed.secure,
        "the caller keeps the secure profile it offered, rather than being downgraded: {answer}"
    );
    let engine_key = parsed
        .crypto
        .first()
        .expect("the answer carries the engine's own a=crypto");
    assert_ne!(
        engine_key.key.to_inline_bytes(),
        caller_key.key.to_inline_bytes(),
        "the engine answers its OWN key, never echoing the caller's back"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secure_caller_reaches_a_plain_callee_through_the_bridge() {
    // End to end: the caller's SRTP is decrypted and relayed to the callee in the clear, and the
    // callee's plaintext comes back encrypted under the engine's own key. This is the topology the
    // change request names — "a secure caller toward a plain callee" — and it could not be built.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_srtp::SrtpContext;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let caller_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("caller key");

    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "secure-relay".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &caller_key),
                profile: Default::default(),
            },
        )
        .await;
    let engine_far = sdp::parse(&ok_sdp_text(&offered))
        .expect("far offer")
        .remote_rtp;
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "secure-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answered)).expect("answer");
    let engine_near = near.remote_rtp;
    let engine_key = *near.crypto.first().expect("the engine's key");

    // A → B: the caller's SRTP arrives, is decrypted, and reaches B as plaintext RTP.
    let mut protect = SrtpContext::from_key_material(&caller_key.key);
    let plain = g711_rtp(0, 7, 0x0A0A_0A0A, 0x20);
    let mut encrypted = Vec::new();
    protect.protect(&plain, &mut encrypted).expect("protect");
    phone_a
        .send_to(&encrypted, engine_near)
        .await
        .expect("caller send");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_millis(500), phone_b.recv_from(&mut buffer))
        .await
        .expect("the callee receives")
        .expect("recv");
    assert_eq!(
        &buffer[..len],
        plain.as_slice(),
        "the callee sees the caller's audio in the clear, byte for byte"
    );

    // B → A: the callee's plaintext comes back encrypted under the engine's own key.
    let reply = g711_rtp(0, 11, 0x0B0B_0B0B, 0x40);
    phone_b
        .send_to(&reply, engine_far)
        .await
        .expect("callee send");
    let (len, _) = timeout(Duration::from_millis(500), phone_a.recv_from(&mut buffer))
        .await
        .expect("the caller receives")
        .expect("recv");
    assert_ne!(
        &buffer[..len],
        reply.as_slice(),
        "a secure caller must never be handed plaintext"
    );
    let mut unprotect = SrtpContext::from_key_material(&engine_key.key);
    let mut decrypted = Vec::new();
    unprotect
        .unprotect(&buffer[..len], &mut decrypted)
        .expect("it authenticates under the engine's own advertised key");
    assert_eq!(
        decrypted, reply,
        "and decrypts to exactly what the callee sent"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secure_offerer_is_refused_where_the_bridge_cannot_carry_it() {
    // The two shapes that are *not* wired refuse rather than answering `ok` and relaying the
    // caller's audio somewhere it should not go. Both need A's `SecureLeg` threaded into the
    // transcoding pipeline, which is the other half of this work.
    let caller_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("caller key");

    // (a) both parties secure — a transcrypt between two different keys.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "both-secure".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &caller_key),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let callee_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("callee key");
    let result = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "both-secure".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdes_offerer_sdp(addr_b, &callee_key),
                profile: Default::default(),
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => {
            assert!(reason.contains("secure-offerer-unsupported"), "{reason}");
            assert!(reason.contains("transcrypt"), "{reason}");
        }
        other => panic!("expected a refusal for secure↔secure, got {other:?}"),
    }

    // (b) a codec mismatch — the secure offerer's leg would have to reach the transcoder.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "secure-transcode".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &caller_key),
                profile: Default::default(),
            },
        )
        .await;
    let result = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "secure-transcode".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => {
            assert!(reason.contains("secure-offerer-unsupported"), "{reason}");
            assert!(reason.contains("codecs differ"), "{reason}");
        }
        other => panic!("expected a refusal for a transcoding secure offerer, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secure_offer_with_no_usable_key_is_refused_not_bridged_in_the_clear() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let savp_without_crypto = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
        ip = addr_a.ip(),
        port = addr_a.port(),
    );
    let result = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "savp-no-key".into(),
                from_tag: "tag-a".into(),
                sdp: savp_without_crypto,
                profile: Default::default(),
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert!(
            reason.contains("secure-offerer-unkeyable"),
            "the refusal names why, got: {reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(!engine.calls.contains_key("savp-no-key"));
    assert_eq!(engine.client_call_count(CLIENT), 0, "no quota slot leaked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_terminates_an_sdes_offerer_on_the_local_pipeline() {
    // This used to be refused outright (`secure-offerer-unsupported`): the answer already minted
    // the engine's own `a=crypto`, but the single-leg pipeline held no `SecureLeg`, so answering
    // would have advertised keying no media path backed. A TLS/SRTP desk phone therefore could not
    // reach an IVR or a voicemail box at all.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let peer_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("peer key");
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-sdes-ivr".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &peer_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&result);
    let parsed = sdp::parse(&answer).expect("the answer parses");
    assert!(
        parsed.secure,
        "the answer keeps the caller's secure profile: {answer}"
    );
    let answered_key = parsed
        .crypto
        .first()
        .expect("the answer carries the engine's own a=crypto");
    assert_ne!(
        answered_key.key.to_inline_bytes(),
        peer_key.key.to_inline_bytes(),
        "the engine answers its OWN key, never echoing the caller's back"
    );
    assert!(
        engine.media().is_transcoding_call("al-sdes-ivr"),
        "the call is on the userspace media pipeline, which is what now holds the SecureLeg"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secure_ivr_decrypts_the_caller_and_answers_it_encrypted() {
    // The property the refusal existed to protect, now proven the other way round: the caller's
    // SRTP is decrypted before the transcoder sees it, and the prompt the engine plays back comes
    // out encrypted under the engine's own key. Answering a secure caller in the clear is the
    // failure this must never have.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_srtp::SrtpContext;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone, addr) = phone().await;
    let peer_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("peer key");
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-sdes-flow".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr, &peer_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&answered)).expect("answer");
    let engine_port = answer.remote_rtp;
    let engine_key = *answer.crypto.first().expect("the engine's key");

    // Play a prompt so the IVR has something to send back.
    use siphon_rtp_media::fanout::MediaSink as _;
    let mut recorder = siphon_rtp_media::wav::WavRecorder::new(8000, 1);
    recorder.write_pcm(&[6000i16; 1600]);
    let played = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "al-sdes-flow".into(),
                from_tag: "tag-a".into(),
                source: PlayMediaSource::Blob {
                    data: recorder.into_wav(),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(played, CmdResult::Ok { .. }),
        "the prompt starts: {played:?}"
    );

    // The caller sends SRTP encrypted under its own key — what an SDES desk phone actually emits.
    let mut protect = SrtpContext::from_key_material(&peer_key.key);
    for sequence in 0..8u16 {
        let plain = g711_rtp(0, sequence, 0x0A0A_0A0A, 0x20);
        let mut encrypted = Vec::new();
        protect.protect(&plain, &mut encrypted).expect("protect");
        phone.send_to(&encrypted, engine_port).await.expect("send");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Everything the caller hears back must authenticate under the engine's advertised key. A
    // plaintext datagram here would be the exact leak this path used to refuse rather than risk.
    let mut unprotect = SrtpContext::from_key_material(&engine_key.key);
    let mut heard = false;
    for _ in 0..40u16 {
        let mut buffer = [0u8; 2048];
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone.recv_from(&mut buffer)).await
        else {
            continue;
        };
        // Skip the periodic RTCP sender report: it rides the same muxed socket (RFC 5761) and is
        // SRTCP, which the SRTP context deliberately cannot authenticate. Under load it can be the
        // first datagram to arrive, so a test that assumed RTP here failed for the wrong reason.
        // RFC 3550 §A.11: a muxed RTCP packet's payload type is 200..=204.
        if matches!(buffer[1] & 0x7F, 200..=204) {
            continue;
        }
        // Authenticating under the engine's advertised key is the whole assertion: SRTP appends a
        // keyed auth tag over the header and the encrypted payload (RFC 3711 §3.1), so a
        // plaintext frame — the leak this path used to refuse rather than risk — cannot pass it.
        let mut plain = Vec::new();
        unprotect
            .unprotect(&buffer[..len], &mut plain)
            .expect("the IVR's egress authenticates under the engine's own key");
        let packet = siphon_rtp_media::rtp::RtpPacket::parse(&plain).expect("decrypted rtp");
        assert_eq!(packet.payload_type, 0, "encoded in the caller's own codec");
        heard = true;
        break;
    }
    assert!(heard, "the secure caller hears the IVR");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_still_refuses_a_dtls_offerer_without_a_takeover() {
    // Deliberately still refused, and it names why: DTLS on the local pipeline needs the full ICE
    // agent on the promoted (`Redirect`) leg so the handshake can be gated on the selected pair,
    // which this change does not build. Answering a fingerprint with no media path behind it is
    // exactly the failure the SDES half just stopped having.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let certificate = siphon_rtp_dtls::DtlsCertificate::generate().expect("cert");
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-dtls-ivr".into(),
                from_tag: "tag-a".into(),
                sdp: dtls_offerer_sdp(addr_a, &certificate.fingerprint(), "actpass"),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => {
            assert!(
                reason.contains("secure-offerer-unsupported"),
                "the refusal keeps its stable token, got: {reason}"
            );
            assert!(
                reason.contains("DTLS"),
                "and names which posture is unsupported, got: {reason}"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(!engine.calls.contains_key("al-dtls-ivr"));
    assert_eq!(engine.client_call_count(CLIENT), 0, "no quota slot leaked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_refuses_a_secure_takeover_it_cannot_key() {
    // A secure profile with nothing to key from is declined, never downgraded to plaintext
    // (docs/security-and-nat.md layer 5): `RTP/SAVP` with no usable `a=crypto`, and
    // `UDP/TLS/RTP/SAVPF` with no `a=fingerprint` to bind the handshake to (RFC 5763 §5).
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;

    let no_crypto = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
        ip = addr_a.ip(),
        port = addr_a.port(),
    );
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-nokey".into(),
                from_tag: "tag-a".into(),
                sdp: no_crypto,
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri.clone()),
                    ..Default::default()
                },
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert!(
            reason.contains("ws-takeover-unkeyable") && reason.contains("a=crypto"),
            "unexpected reason: {reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }

    let no_fingerprint = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
             a=setup:actpass\r\n",
        ip = addr_a.ip(),
        port = addr_a.port(),
    );
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-nofp".into(),
                from_tag: "tag-a".into(),
                sdp: no_fingerprint,
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert!(
            reason.contains("ws-takeover-unkeyable") && reason.contains("a=fingerprint"),
            "unexpected reason: {reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(engine.client_call_count(CLIENT), 0, "no quota slot leaked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answer_local_refuses_a_ws_takeover_on_an_ice_offerer_without_the_full_agent() {
    // A takeover leg's egress belongs to the bridge's drain task, and only the full RFC 8445
    // agent's selection re-points it. The ice-lite responder adopts into the datapath's own latch,
    // which gates a `Forward` rule — and a takeover leg is `Redirect`, so that gate never runs.
    // Refuse rather than ship a leg that is open at layer 2 and deaf at layer 4.
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new()); // no `--ice-full`
    let (_phone_a, addr_a) = phone().await;
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-ice-lite".into(),
                from_tag: "tag-a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri.clone()),
                    ..Default::default()
                },
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert!(
            reason.contains("ws-takeover-ice-unsupported"),
            "the refusal must name the reason, got: {reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(!engine.calls.contains_key("al-ice-lite"));
    assert_eq!(engine.client_call_count(CLIENT), 0, "no quota slot leaked");

    // `ICE=remove` is the documented escape hatch: the peer's ICE is stripped and the leg falls
    // back to the signalled address, which the bridge can serve.
    let accepted = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-ice-removed".into(),
                from_tag: "tag-a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ice: Some("remove".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(
        matches!(accepted, CmdResult::Ok { .. }),
        "ICE=remove must still be accepted: {accepted:?}"
    );
    assert!(engine.ws().is_ws_call("al-ice-removed"));
    let stripped = sdp::parse(&ok_sdp_text(&accepted)).expect("answer sdp");
    assert!(
        !stripped.is_ice(),
        "ICE=remove strips the peer's ICE rather than echoing its credentials back"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_ice_ws_takeover_carries_media_only_after_the_agent_selects_a_pair() {
    // The takeover analogue of the two-party full-ICE proof: a real peer agent runs against the
    // engine's, nothing crosses the leg until the agent selects (RFC 8445 §12), and the selection
    // re-points the bridge's downlink at the chosen pair (§8.1.1) instead of the signalled `c=`.
    use crate::srtp_bridge::run_redirect_dispatcher;

    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;

    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ice-takeover".into(),
                from_tag: "tag-a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&result)).expect("answer sdp");
    assert!(engine.ws().is_ws_call("ice-takeover"));
    assert_ne!(
        answer.ice_ufrag.as_deref(),
        Some(A_UFRAG),
        "the answer re-originates the engine's own ICE credentials, not the peer's echoed back"
    );
    assert!(
        !answer.candidates.is_empty(),
        "the answer carries the engine's gathered candidates"
    );
    let engine_media = answer.remote_rtp;
    let near_rtp = engine
        .calls
        .get("ice-takeover")
        .map(|call| call.near.rtp.id)
        .expect("call");

    // Media before the agent decides is dropped, even though it comes from the signalled source.
    expect_ws_start(&frames).await;
    for sequence in 0..5u16 {
        phone_a
            .send_to(&ulaw_rtp_packet(sequence, 0x0E0E_0E0E, 0xFF), engine_media)
            .await
            .expect("early media");
    }
    assert!(
        timeout(Duration::from_millis(300), frames.recv_async())
            .await
            .is_err(),
        "no audio reaches the WS server before ICE selects a pair"
    );

    // Drive both agents until the engine selects.
    let mut peer = peer_agent(&answer, addr_a);
    let mut buffer = [0u8; 2048];
    let mut now = 0u64;
    while now < 4_000 && engine.datapath().ice_validated_source(near_rtp).is_none() {
        for action in peer.poll(now) {
            if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                phone_a.send_to(&datagram, to).await.expect("peer send");
            }
        }
        engine.drive_ice_agents(now).await;
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(20), phone_a.recv_from(&mut buffer)).await
        {
            for action in peer.on_datagram(addr_a, from, &buffer[..len], now) {
                if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                    phone_a.send_to(&datagram, to).await.expect("peer send");
                }
            }
            engine.drive_ice_agents(now).await;
        }
        now += 20;
    }
    assert_eq!(
        engine.datapath().ice_validated_source(near_rtp),
        Some(addr_a),
        "the agent selected the peer's transport address"
    );

    // …and now the takeover leg carries audio to the WS server.
    for sequence in 0..5u16 {
        phone_a
            .send_to(&ulaw_rtp_packet(sequence, 0x0E0E_0E0E, 0xFF), engine_media)
            .await
            .expect("media");
    }
    let uplink = next_uplink_frame(&frames)
        .await
        .expect("audio reaches the WS server once the pair is selected");
    assert_eq!(uplink.len(), 320, "8k/20ms L16 uplink");
}

/// A minimal 8 kHz mono 16-bit PCM RIFF/WAVE prompt blob for `play_media`.
fn prompt_wav_blob(sample_count: usize) -> Vec<u8> {
    let data_len = (sample_count * 2) as u32;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"RIFF");
    buffer.extend_from_slice(&(36 + data_len).to_le_bytes());
    buffer.extend_from_slice(b"WAVE");
    buffer.extend_from_slice(b"fmt ");
    buffer.extend_from_slice(&16u32.to_le_bytes());
    buffer.extend_from_slice(&1u16.to_le_bytes()); // PCM
    buffer.extend_from_slice(&1u16.to_le_bytes()); // mono
    buffer.extend_from_slice(&8000u32.to_le_bytes()); // sample rate
    buffer.extend_from_slice(&16000u32.to_le_bytes()); // byte rate
    buffer.extend_from_slice(&2u16.to_le_bytes()); // block align
    buffer.extend_from_slice(&16u16.to_le_bytes()); // bits per sample
    buffer.extend_from_slice(b"data");
    buffer.extend_from_slice(&data_len.to_le_bytes());
    for index in 0..sample_count {
        buffer.extend_from_slice(&((index as i16).wrapping_mul(7)).to_le_bytes());
    }
    buffer
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_egress_on_a_secure_takeover_leg_is_encrypted() {
    // The audit this repo has already been bitten by once: a secure call whose media path is
    // correct but which has a *second* emitter that pushes plaintext (the telephone-event relay
    // and the injected-DTMF tick, both fixed earlier). A takeover call must have exactly one
    // egress site — the bridge's downlink drain — so this test proves the two halves of that:
    //
    // 1. every other verb that can put a packet on the wire refuses a takeover call, and
    // 2. every datagram that actually reaches the caller decrypts under the advertised key, i.e.
    //    not one of them is plaintext.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_media::bridge::pcm_to_l16_le;

    let (ws_uri, _frames, downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let peer_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("peer key");
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "egress-audit".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &peer_key),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&result)).expect("answer sdp");
    let engine_key = answer.crypto.first().copied().expect("engine a=crypto");
    let mut caller_leg = SecureLeg::new(&peer_key.key, &engine_key.key);

    // 1. No second emitter. Each of these can put a packet on the wire on some other pipeline; on
    //    a takeover call every one of them must refuse rather than find a way to emit.
    let refusals: Vec<(&str, CmdResult)> = vec![
        (
            "play_media",
            engine
                .handle(
                    CLIENT,
                    Command::PlayMedia {
                        call_id: "egress-audit".into(),
                        from_tag: "tag-a".into(),
                        to_tag: None,
                        // A *valid* prompt, so the refusal comes from the missing pipeline and
                        // not from a WAV parse error further up.
                        source: PlayMediaSource::Blob {
                            data: prompt_wav_blob(320),
                        },
                        repeat_times: None,
                        start_pos_ms: None,
                        duration_ms: None,
                        overlay: false,
                        gain_decibels: None,
                    },
                )
                .await,
        ),
        (
            "play_dtmf",
            engine
                .handle(
                    CLIENT,
                    Command::PlayDtmf {
                        call_id: "egress-audit".into(),
                        from_tag: "tag-a".into(),
                        to_tag: None,
                        code: "1".into(),
                        duration_ms: None,
                        volume_dbm0: None,
                        pause_ms: None,
                    },
                )
                .await,
        ),
        (
            "silence_media",
            engine
                .handle(
                    CLIENT,
                    Command::SilenceMedia {
                        call_id: "egress-audit".into(),
                        from_tag: "tag-a".into(),
                    },
                )
                .await,
        ),
        (
            "echo",
            engine
                .handle(
                    CLIENT,
                    Command::Echo {
                        call_id: "egress-audit".into(),
                        from_tag: "tag-a".into(),
                        to_tag: None,
                        enabled: true,
                    },
                )
                .await,
        ),
        (
            "block_dtmf",
            engine
                .handle(
                    CLIENT,
                    Command::BlockDtmf {
                        call_id: "egress-audit".into(),
                        from_tag: "tag-a".into(),
                        to_tag: None,
                    },
                )
                .await,
        ),
        (
            "start_recording",
            engine
                .handle(
                    CLIENT,
                    Command::StartRecording {
                        call_id: "egress-audit".into(),
                        from_tag: "tag-a".into(),
                        recording_dir: None,
                        format: None,
                        direction: None,
                        channels: None,
                        max_duration_ms: None,
                        silence_ms: None,
                        path: None,
                    },
                )
                .await,
        ),
        (
            "attach_ws_tee",
            engine
                .handle(
                    CLIENT,
                    Command::AttachWsTee {
                        call_id: "egress-audit".into(),
                        from_tag: "tag-a".into(),
                        ws_uri: "ws://127.0.0.1:1/tee".into(),
                        direction: WsTeeDirection::Caller,
                        channels: None,
                        sample_rate: None,
                    },
                )
                .await,
        ),
    ];
    for (verb, result) in refusals {
        match result {
            CmdResult::Error { reason } => {
                if verb == "play_media" {
                    // Pin the *reason*: the prompt is a valid WAV, so a refusal that mentions
                    // parsing would mean this case is passing for the wrong reason and the real
                    // guard (no pipeline to inject into) is still absent.
                    assert!(
                        reason.contains("media-processing"),
                        "play_media must refuse because there is no pipeline to inject into, \
                             got: {reason}"
                    );
                }
            }
            other => panic!(
                "{verb} must refuse a WebSocket-takeover call rather than emit on it: {other:?}"
            ),
        }
    }

    // 2. Everything the caller actually receives is SRTP. Push several downlink frames and audit
    //    every datagram: a single plaintext one fails the test.
    let mut l16 = [0u8; 320];
    pcm_to_l16_le(&[2000i16; 160], &mut l16);
    for _ in 0..5 {
        downlink.send(l16.to_vec()).expect("queue downlink");
    }
    let mut buffer = [0u8; 2048];
    let mut audited = 0usize;
    for _ in 0..40 {
        let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        else {
            continue;
        };
        let datagram = &buffer[..len];
        let mut clear = Vec::new();
        assert!(
            caller_leg.unprotect(datagram, &mut clear).is_ok(),
            "a takeover leg on a secure offerer emitted a datagram the peer cannot decrypt \
                 (plaintext leak or wrong key): {datagram:02x?}"
        );
        audited += 1;
        if audited >= 3 {
            break;
        }
    }
    assert!(
        audited >= 1,
        "expected the WS downlink to reach the caller so there is something to audit"
    );
}

#[test]
fn ws_takeover_security_resolves_the_offerers_own_posture() {
    // Unit cover for the resolver every single-leg verb branches on. It reads the offerer's SDP
    // and nothing else: it used to take a `takeover` flag and refuse a secure offerer without
    // one, which is no longer its decision to make — the local pipeline terminates SDES now, and
    // which media paths can honour a resolved posture is the caller's business.
    let plain = sdp::parse(plain_offer_sdp()).expect("plain offer");
    assert!(matches!(
        resolve_offerer_security(&plain),
        Ok(WsTakeoverSecurity::Plain)
    ));

    let key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("key");
    let address: SocketAddr = "203.0.113.7:30000".parse().expect("addr");
    let sdes = sdp::parse(&sdes_offerer_sdp(address, &key)).expect("sdes offer");
    match resolve_offerer_security(&sdes) {
        Ok(WsTakeoverSecurity::Sdes { peer_key }) => assert_eq!(
            peer_key.key.to_inline_bytes(),
            key.key.to_inline_bytes(),
            "the offerer's own key is carried through"
        ),
        other => panic!("expected Sdes, got {other:?}"),
    }

    let certificate = siphon_rtp_dtls::DtlsCertificate::generate().expect("cert");
    let fingerprint = certificate.fingerprint();
    let dtls = sdp::parse(&dtls_offerer_sdp(address, &fingerprint, "active")).expect("dtls offer");
    match resolve_offerer_security(&dtls) {
        Ok(WsTakeoverSecurity::Dtls {
            peer_fingerprint,
            peer_setup,
        }) => {
            assert_eq!(peer_fingerprint.bytes, fingerprint.bytes);
            assert_eq!(peer_setup, Some(sdp::Setup::Active));
        }
        other => panic!("expected Dtls, got {other:?}"),
    }

    // A secure profile with nothing to key from is refused, never downgraded to plaintext.
    let no_crypto = sdp::parse(
        "v=0\r\no=- 1 1 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\n\
             m=audio 30000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
    )
    .expect("savp without crypto");
    match resolve_offerer_security(&no_crypto) {
        Err(reason) => assert!(
            reason.contains("ws-takeover-unkeyable") && reason.contains("a=crypto"),
            "{reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    let no_fingerprint = sdp::parse(
        "v=0\r\no=- 1 1 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\n\
             m=audio 30000 UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=setup:actpass\r\n",
    )
    .expect("dtls without fingerprint");
    match resolve_offerer_security(&no_fingerprint) {
        Err(reason) => assert!(
            reason.contains("ws-takeover-unkeyable") && reason.contains("a=fingerprint"),
            "{reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secure_takeover_call_refuses_ha_checkpoint() {
    // HA is unchanged by securing the leg, and this pins that it stays honest rather than handing
    // back a blob that would restore as something that never existed. A takeover's far side is an
    // external WebSocket session — not replicable state — and `answer_local` holds a single leg,
    // so `checkpoint` refuses outright (`restore` separately rejects a `Ws` snapshot).
    let (ws_uri, _frames, _downlink) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let peer_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("peer key");
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "secure-takeover-ha".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &peer_key),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");

    let checkpoint = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "secure-takeover-ha".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    match checkpoint {
        CmdResult::Error { reason } => assert!(
            reason.contains("single-leg"),
            "the refusal must say why, got: {reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn answer_local_ws_takeover_does_not_negotiate_comfort_noise() {
    // CN egress is generated by the promoted media actor, which a takeover call does not have. The
    // answer must therefore not advertise CN it can never send (the non-WS path still negotiates
    // it — `answer_local_negotiates_offered_comfort_noise` pins that).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let ws_addr = ws_listener.local_addr().expect("ws addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = ws_listener.accept().await {
            let _ = tokio_tungstenite::accept_async(stream).await;
        }
    });

    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 13 101\r\na=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\n",
        port = addr_a.port()
    );
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-ws-cn".into(),
                from_tag: "tag-a".into(),
                sdp: offer,
                profile: ProfileFlags {
                    ws_uri: Some(format!("ws://{ws_addr}/stream")),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = ok_sdp_text(&result);
    assert!(
        !answer.contains("a=rtpmap:13"),
        "a takeover answer must not advertise CN it cannot send: {answer}"
    );
    let call = engine.calls.get("al-ws-cn").expect("call present");
    assert!(call.comfort_noise_payload_type.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_attaches_leg_a_to_a_secure_websocket_server_over_wss() {
    // The `wss://` counterpart of the plain-`ws://` bridge test: a control client sets a `wss://`
    // `ws_uri`, and the engine dials it over TLS (RFC 8446 handshake on the ring/rustls provider,
    // RFC 6455 upgrade) before streaming. Proves the ring-backed connector completes the TLS +
    // WebSocket handshake end-to-end and the mod_audio_stream `start` frame flows over the tunnel.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use futures_util::StreamExt;
    use siphon_rtp_media::bridge::protocol::ControlMessage;
    use tokio_tungstenite::tungstenite::Message;

    // Ring is the only crypto provider compiled (rustls `default-features = false, ["ring"]`);
    // install it as the process default so the test-side rustls configs build on it too.
    siphon_rtp_turn::tls::install_crypto_provider();

    // A fresh self-signed certificate for the loopback IP the engine will dial (IP SAN so rustls
    // validates the `ServerName::IpAddress` derived from `wss://127.0.0.1:...`).
    let certified =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).expect("gen cert");
    let cert_der = rustls_pki_types::CertificateDer::from(certified.cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::Pkcs8(
        rustls_pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
    );
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server tls config");
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

    // A TLS WebSocket server: TLS-accept the connection, run the WS handshake over the tunnel, and
    // relay every received frame out `ws_rx`.
    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wss");
    let ws_addr = ws_listener.local_addr().expect("wss addr");
    let (ws_tx, ws_rx) = flume::unbounded::<Message>();
    tokio::spawn(async move {
        let (stream, _) = ws_listener.accept().await.expect("accept tcp");
        let tls_stream = acceptor.accept(stream).await.expect("tls handshake");
        let socket = tokio_tungstenite::accept_async(tls_stream)
            .await
            .expect("wss handshake");
        let (_sink, mut source) = socket.split();
        while let Some(incoming) = source.next().await {
            match incoming {
                Ok(message) => {
                    if ws_tx.send(message).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let engine = Engine::new(UdpLoopbackDatapath::new());
    // Pre-seed the engine's `wss://` client trust store with the self-signed test certificate so
    // the dial validates it (production seeds from the webpki-roots Mozilla CA bundle instead).
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).expect("add test root");
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    engine
        .ws_tls_config
        .set(std::sync::Arc::new(client_config))
        .expect("seed wss client config");

    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (_phone_a, addr_a) = phone().await;

    // A offers PCMU with a `wss://` `ws_uri` → the engine dials the TLS WS and bridges leg A.
    let profile = ProfileFlags {
        ws_uri: Some(format!("wss://127.0.0.1:{}/stream", ws_addr.port())),
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "wss-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile,
            },
        )
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "wss offer succeeds");
    assert!(
        engine.ws().is_ws_call("wss-1"),
        "the call is a WS-bridge call"
    );

    // The TLS WebSocket server receives the `start` text frame first — proof the TLS handshake and
    // the WS upgrade both completed over `wss://`.
    let first = timeout(Duration::from_secs(3), ws_rx.recv_async())
        .await
        .expect("no timeout")
        .expect("a frame");
    match first {
        Message::Text(text) => assert!(
            matches!(
                ControlMessage::from_json(text.as_str()),
                Ok(ControlMessage::Start(_))
            ),
            "first WSS frame is `start`"
        ),
        other => panic!("expected start text frame over wss, got {other:?}"),
    }

    // Teardown frees the secure WS bridge.
    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "wss-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));
    assert!(
        !engine.ws().is_ws_call("wss-1"),
        "WSS call deregistered on delete"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_dtmf_emits_telephone_events_on_a_media_call() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    // A offers PCMU + telephone-event 101; B answers PCMA + telephone-event 101 → a transcoding
    // media call where A's leg carries DTMF.
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
        ip = addr_a.ip(),
        port = addr_a.port(),
    );
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
        ip = addr_b.ip(),
        port = addr_b.port(),
    );
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtmf-1".into(),
                from_tag: "tag-a".into(),
                sdp: offer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dtmf-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: answer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    assert!(engine.media().is_media_call("dtmf-1"));

    // Play DTMF '7' toward A; the actor's playout clock injects RFC 4733 events out A's socket.
    let played = engine
        .handle(
            CLIENT,
            Command::PlayDtmf {
                call_id: "dtmf-1".into(),
                from_tag: "tag-a".into(),
                code: "7".into(),
                duration_ms: Some(120),
                volume_dbm0: Some(-10),
                pause_ms: None,
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(played, CmdResult::Ok { .. }));

    // The first telephone-event packet (PT 96) reaches A within a few playout ticks.
    let mut saw_event = false;
    for _ in 0..20 {
        let mut buffer = [0u8; 256];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(100), phone_a.recv_from(&mut buffer)).await
        {
            let packet = siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse");
            if packet.payload_type == 101 {
                assert_eq!(packet.payload[0], 7, "RFC 4733 event code for '7'");
                saw_event = true;
                break;
            }
        }
    }
    assert!(saw_event, "expected a telephone-event packet toward A");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_dtmf_plays_every_digit_of_a_multi_digit_code() {
    // B11/B14: a multi-digit `code` plays in full — every digit reaches the peer as its own RFC
    // 4733 event — not truncated to the first digit, and `pause_ms` separates them.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
        ip = addr_a.ip(),
        port = addr_a.port(),
    );
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
        ip = addr_b.ip(),
        port = addr_b.port(),
    );
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtmf-multi".into(),
                from_tag: "tag-a".into(),
                sdp: offer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dtmf-multi".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: answer_sdp,
                profile: Default::default(),
            },
        )
        .await;

    let played = engine
        .handle(
            CLIENT,
            Command::PlayDtmf {
                call_id: "dtmf-multi".into(),
                from_tag: "tag-a".into(),
                code: "12".into(),
                duration_ms: Some(80),
                volume_dbm0: Some(-10),
                pause_ms: Some(40),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(played, CmdResult::Ok { .. }));

    let mut saw_one = false;
    let mut saw_two = false;
    for _ in 0..80 {
        let mut buffer = [0u8; 256];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(100), phone_a.recv_from(&mut buffer)).await
        {
            let packet = siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse");
            if packet.payload_type == 101 {
                match packet.payload[0] {
                    1 => saw_one = true,
                    2 => saw_two = true,
                    other => panic!("unexpected DTMF event code {other}"),
                }
            }
        }
        if saw_one && saw_two {
            break;
        }
    }
    assert!(
        saw_one && saw_two,
        "both digits of the code played toward A (not truncated to the first)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_dtmf_rejects_an_unsupported_digit_instead_of_truncating() {
    // A non-DTMF character is a clean client error, never a silent drop / truncation (B14).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
        ip = addr_a.ip(),
        port = addr_a.port(),
    );
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=rtcp-mux\r\n",
        ip = addr_b.ip(),
        port = addr_b.port(),
    );
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtmf-bad".into(),
                from_tag: "tag-a".into(),
                sdp: offer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dtmf-bad".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: answer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    let result = engine
        .handle(
            CLIENT,
            Command::PlayDtmf {
                call_id: "dtmf-bad".into(),
                from_tag: "tag-a".into(),
                code: "1Z2".into(),
                duration_ms: None,
                volume_dbm0: None,
                pause_ms: None,
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(result, CmdResult::Error { .. }),
        "an unsupported DTMF digit is rejected, not truncated"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_dtmf_toward_a_leg_with_no_telephone_event_is_an_error_not_a_silent_no_op() {
    // The defect: the engine answered from whether the control message reached the actor's
    // mailbox, so a `play_dtmf` toward a leg that never negotiated `telephone-event` was accepted
    // and nothing went on the wire. On a PBX that is a feature code forwarded to a carrier or a
    // flow step navigating a remote menu, and a silent no-op there reads as the far end ignoring
    // the digits.
    //
    // A transcoding call (µ-law ↔ A-law, so the media path is userspace) where **neither** party
    // offered a telephone-event payload type.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
        ip = addr_a.ip(),
        port = addr_a.port(),
    );
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=rtcp-mux\r\n",
        ip = addr_b.ip(),
        port = addr_b.port(),
    );
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtmf-none".into(),
                from_tag: "tag-a".into(),
                sdp: offer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dtmf-none".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: answer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        engine.media().is_transcoding_call("dtmf-none"),
        "the codec mismatch puts this call on the userspace media path"
    );

    let result = engine
        .handle(
            CLIENT,
            Command::PlayDtmf {
                call_id: "dtmf-none".into(),
                from_tag: "tag-a".into(),
                code: "123".into(),
                duration_ms: None,
                volume_dbm0: None,
                pause_ms: None,
                to_tag: Some("tag-b".into()),
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert!(
            reason.contains("no telephone-event payload type negotiated"),
            "the refusal names why nothing could be sent, got: {reason}"
        ),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_rejects_a_mismatched_to_tag() {
    // B18: `to_tag` on echo is no longer inert — a to-tag that does not name this call's UAS leg
    // is a clean error rather than silently ignored, while the correct to-tag is accepted.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "echo-tt".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "echo-tt".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let mismatched = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-tt".into(),
                from_tag: "tag-a".into(),
                to_tag: Some("not-the-to-tag".into()),
                enabled: true,
            },
        )
        .await;
    assert!(
        matches!(mismatched, CmdResult::Error { .. }),
        "a to_tag that does not match the call is rejected"
    );
    let matched = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-tt".into(),
                from_tag: "tag-a".into(),
                to_tag: Some("tag-b".into()),
                enabled: true,
            },
        )
        .await;
    assert!(
        matches!(matched, CmdResult::Ok { .. }),
        "the call's real to-tag is accepted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_replace_unsupported_token_still_succeeds_without_rewriting_origin() {
    // B15: an unimplemented `replace` token is surfaced (logged), not a hard failure — a common
    // rtpengine controller sending `session-connection` must still complete its offer, and without
    // `origin` the o= address is left untouched (topology hiding is not silently applied).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let offer_sdp = format!(
        "v=0\r\no=alice 1 1 IN IP4 10.0.0.7\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n",
        ip = addr.ip(),
        port = addr.port()
    );
    let profile = ProfileFlags {
        replace: vec!["session-connection".into()],
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ro-unknown".into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile,
            },
        )
        .await;
    let sdp = ok_sdp_text(&offer);
    let o_line = sdp.lines().find(|l| l.starts_with("o=")).expect("o= line");
    assert!(
        o_line.contains("10.0.0.7"),
        "without `origin`, the o= address is not rewritten: {o_line}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silence_on_a_passthrough_call_is_rejected() {
    // A plain relay (same codec both sides) is not a media-processing call; silence needs decode.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "relay-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "relay-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let result = engine
        .handle(
            CLIENT,
            Command::SilenceMedia {
                call_id: "relay-1".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(result, CmdResult::Error { .. }),
        "silence needs a media call"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_relays_rtp_then_query_and_delete() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    let far_rtp = sdp::parse(&ok_sdp_text(&offer))
        .expect("parse far")
        .remote_rtp;

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let near_rtp = sdp::parse(&ok_sdp_text(&answer))
        .expect("parse near")
        .remote_rtp;

    phone_a
        .send_to(&rtp(0x0A0A_0A0A), near_rtp)
        .await
        .expect("send a");
    let (data, from) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A));
    assert_eq!(from, far_rtp);

    phone_b
        .send_to(&rtp(0x0B0B_0B0B), far_rtp)
        .await
        .expect("send b");
    let (data, from) = recv(&phone_a).await;
    assert_eq!(data, rtp(0x0B0B_0B0B));
    assert_eq!(from, near_rtp);

    // Stats: poll for packets_out to settle (counted after the forwarding send).
    let mut stats = SessionStats::default();
    for _ in 0..50 {
        if let CmdResult::Ok { stats: Some(s), .. } = engine
            .handle(
                CLIENT,
                Command::Query {
                    call_id: "call-1".into(),
                    from_tag: "tag-a".into(),
                    to_tag: None,
                },
            )
            .await
        {
            stats = s;
        }
        if stats.packets_out == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(stats.packets_in, 2);
    assert_eq!(stats.packets_out, 2);

    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "call-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(delete, CmdResult::Ok { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_honours_direction_bind_and_advertised_ips() {
    // Two named interfaces on loopback (127/8 is all loopback on Linux, so distinct 127.0.0.x
    // addresses exercise per-leg source-IP selection + advertised-IP override NIC-free):
    //   internal → bind 127.0.0.1 (advertise the same),
    //   external → bind 127.0.0.2 but advertise a *distinct* public IP 127.0.0.3.
    // direction=[external, internal] puts the A-facing (near) leg on external and the B-facing
    // (far) leg on internal — rtpengine semantics.
    let table = InterfaceTable::from_entries(
        vec![
            crate::interface::InterfaceEntry::new("internal", "127.0.0.1".parse().unwrap(), None),
            crate::interface::InterfaceEntry::new(
                "external",
                "127.0.0.2".parse().unwrap(),
                Some("127.0.0.3".parse().unwrap()),
            ),
        ],
        None,
    )
    .expect("interface table");
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_interfaces(table);
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    let profile = ProfileFlags {
        direction: vec!["external".into(), "internal".into()],
        ..Default::default()
    };
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "call-dir".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: profile.clone(),
            },
        )
        .await;
    let offer_sdp = ok_sdp_text(&offer);
    // The offer goes to B, advertising the far (internal) leg: bound and advertised are both
    // 127.0.0.1.
    assert!(
        offer_sdp.contains("c=IN IP4 127.0.0.1"),
        "far leg advertises the internal interface: {offer_sdp}"
    );
    let far = sdp::parse(&offer_sdp).expect("parse far").remote_rtp;
    assert_eq!(far.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "call-dir".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, false),
                profile,
            },
        )
        .await;
    let answer_sdp = ok_sdp_text(&answer);
    // The answer goes to A, advertising the near (external) leg's *advertised public* IP
    // 127.0.0.3 — decoupled from the bound socket, which is on 127.0.0.2.
    assert!(
        answer_sdp.contains("c=IN IP4 127.0.0.3"),
        "near leg advertises the external public IP, not the bind IP: {answer_sdp}"
    );
    let near_advertised = sdp::parse(&answer_sdp).expect("parse near").remote_rtp;
    assert_eq!(
        near_advertised.ip(),
        "127.0.0.3".parse::<std::net::IpAddr>().unwrap()
    );

    // Media actually flows on the *bound* near IP (127.0.0.2), not the advertised 127.0.0.3
    // (a stand-in public IP nothing is bound on). A sends to the bound near address; the packet
    // relays out of the far (internal, 127.0.0.1) leg to B.
    let near_bound = SocketAddr::new("127.0.0.2".parse().unwrap(), near_advertised.port());
    phone_a
        .send_to(&rtp(0x0A0A_0A0A), near_bound)
        .await
        .expect("send a");
    let (data, from) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A));
    assert_eq!(
        from, far,
        "B receives the relayed packet from the far (internal) bound leg on 127.0.0.1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_advertises_the_public_ip_while_binding_private() {
    // The single-homed 1:1-NAT / AWS Elastic-IP case (`--advertise-ip`): bind a private address
    // (127.0.0.2 stands in for the VPC IP), advertise a public one (127.0.0.3 = the EIP), no
    // `direction` — exactly the one synthesised `default` interface the daemon builds from
    // relay_bind_ip + advertise_ip.
    let table = InterfaceTable::single(
        "127.0.0.2".parse().unwrap(),
        Some("127.0.0.3".parse().unwrap()),
    );
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_interfaces(table);
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "adv".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    let offer_sdp = ok_sdp_text(&offer);
    assert!(
        offer_sdp.contains("c=IN IP4 127.0.0.3"),
        "offer advertises the public EIP: {offer_sdp}"
    );
    assert!(
        !offer_sdp.contains("127.0.0.2"),
        "the private bind IP never appears in SDP: {offer_sdp}"
    );
    let far_advertised = sdp::parse(&offer_sdp).expect("parse far").remote_rtp;

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "adv".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let answer_sdp = ok_sdp_text(&answer);
    assert!(
        answer_sdp.contains("c=IN IP4 127.0.0.3"),
        "answer advertises the public EIP: {answer_sdp}"
    );
    let near_advertised = sdp::parse(&answer_sdp).expect("parse near").remote_rtp;

    // Media flows on the *private* bound IP (127.0.0.2), not the advertised public one; the port
    // is identical (1:1 NAT preserves it).
    let near_bound = SocketAddr::new("127.0.0.2".parse().unwrap(), near_advertised.port());
    phone_a
        .send_to(&rtp(0x0A0A_0A0A), near_bound)
        .await
        .expect("send a");
    let (data, from) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A));
    assert_eq!(
        from.ip(),
        "127.0.0.2".parse::<std::net::IpAddr>().unwrap(),
        "B receives from the far leg's bound *private* IP, not the advertised public one"
    );
    assert_eq!(
        from.port(),
        far_advertised.port(),
        "same port on both sides (1:1 NAT)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn advertise_ip_v4_does_not_land_on_a_v6_leg() {
    // Family guard: a v4 advertise-ip must never appear in a `c=IN IP6` line (invalid SDP). A v6
    // offer's engine leg advertises its bound v6 address, not the v4 public IP.
    let table = InterfaceTable::single(
        "127.0.0.2".parse().unwrap(),
        Some("127.0.0.3".parse().unwrap()),
    );
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_interfaces(table);
    let (_phone_a, addr_a) = phone_v6().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "v6".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    let offer_sdp = ok_sdp_text(&offer);
    assert!(
        offer_sdp.contains("c=IN IP6 ::1"),
        "the v6 leg advertises its bound v6 address: {offer_sdp}"
    );
    assert!(
        !offer_sdp.contains("127.0.0.3"),
        "the v4 advertise-ip must not land on a v6 leg: {offer_sdp}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_relays_rtp_over_ipv6_loopback() {
    // End-to-end on IPv6 (RFC 4566 §5.7 `c=IN IP6`): an `IN IP6 ::1` offer/answer must allocate
    // v6 engine endpoints, advertise `c=IN IP6`, and relay RTP between two `::1` phones. Mirrors
    // `offer_answer_relays_rtp_then_query_and_delete` on v6 loopback. `::1` binds in this
    // environment (verified), so this test runs unconditionally; it would only need gating on a
    // host without an IPv6 loopback.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone_v6().await;
    let (phone_b, addr_b) = phone_v6().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "call-v6".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    let offer_sdp = ok_sdp_text(&offer);
    assert!(
        offer_sdp.contains("c=IN IP6 ::1"),
        "v6 offer rewrite: {offer_sdp}"
    );
    let far_rtp = sdp::parse(&offer_sdp).expect("parse far").remote_rtp;
    assert!(far_rtp.is_ipv6(), "the far engine endpoint is v6");

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "call-v6".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let answer_sdp = ok_sdp_text(&answer);
    assert!(
        answer_sdp.contains("c=IN IP6 ::1"),
        "v6 answer rewrite: {answer_sdp}"
    );
    let near_rtp = sdp::parse(&answer_sdp).expect("parse near").remote_rtp;
    assert!(near_rtp.is_ipv6(), "the near engine endpoint is v6");

    // A -> engine -> B over v6 loopback.
    phone_a
        .send_to(&rtp(0x0A0A_0A0A), near_rtp)
        .await
        .expect("send a");
    let (data, from) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A));
    assert_eq!(from, far_rtp);

    // B -> engine -> A over v6 loopback.
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), far_rtp)
        .await
        .expect("send b");
    let (data, from) = recv(&phone_a).await;
    assert_eq!(data, rtp(0x0B0B_0B0B));
    assert_eq!(from, near_rtp);

    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "call-v6".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(delete, CmdResult::Ok { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn companion_rtcp_relays_on_separate_ports() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    // RTP + RTCP sockets per phone (RTCP is the RTP port's logical +1 peer; here just sockets).
    let (rtp_a, addr_rtp_a) = phone().await;
    let (rtcp_a, addr_rtcp_a) = phone().await;
    let (rtp_b, addr_rtp_b) = phone().await;
    let (rtcp_b, addr_rtcp_b) = phone().await;

    // Build offers whose a=rtcp points at the dedicated RTCP socket.
    let offer_sdp = format!(
        "v=0\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\na=rtcp:{}\r\n",
        addr_rtp_a.port(),
        addr_rtcp_a.port()
    );
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "rtcp-call".into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
    assert_ne!(
        far.remote_rtcp.port(),
        far.remote_rtp.port() + 1,
        "engine RTCP is its own port"
    );

    let answer_sdp = format!(
        "v=0\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio {} RTP/AVP 0\r\na=rtcp:{}\r\n",
        addr_rtp_b.port(),
        addr_rtcp_b.port()
    );
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "rtcp-call".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

    // RTP relays on the RTP ports.
    rtp_a
        .send_to(&rtp(0x0A0A_0A0A), near.remote_rtp)
        .await
        .expect("rtp a");
    assert_eq!(recv(&rtp_b).await.0, rtp(0x0A0A_0A0A));

    // RTCP relays on the dedicated RTCP ports (RTCP SR, first byte 0x80 / PT 200).
    let rtcp_sr = vec![0x80u8, 0xC8, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44];
    rtcp_a
        .send_to(&rtcp_sr, near.remote_rtcp)
        .await
        .expect("rtcp a");
    let (data, from) = recv(&rtcp_b).await;
    assert_eq!(data, rtcp_sr);
    assert_eq!(
        from, far.remote_rtcp,
        "B's RTCP arrives from the engine far-RTCP port"
    );

    let _ = (addr_rtcp_a, addr_rtcp_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rtcp_mux_relays_both_on_one_port() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "mux".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
    assert!(far.rtcp_mux);
    assert!(
        !ok_sdp_text(&offer).contains("a=rtcp:"),
        "no companion port advertised under mux"
    );

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "mux".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

    // Both an RTP-looking and an RTCP-looking datagram relay over the single muxed port.
    phone_a
        .send_to(b"\x80\x00rtp", near.remote_rtp)
        .await
        .expect("rtp");
    assert_eq!(recv(&phone_b).await.0, b"\x80\x00rtp");
    phone_b
        .send_to(b"\x80\xc8rtcp", far.remote_rtp)
        .await
        .expect("rtcp");
    assert_eq!(recv(&phone_a).await.0, b"\x80\xc8rtcp");
}

/// An offer profile carrying an `rtcp-mux` directive list.
fn mux_profile(directive: &str) -> ProfileFlags {
    ProfileFlags {
        rtcp_mux: vec![directive.to_string()],
        ..Default::default()
    }
}

#[tokio::test]
async fn rtcp_mux_offer_directive_forces_mux_and_allocates_one_far_port() {
    // rtpengine `rtcp-mux: [offer]` forces the generated (far) SDP to advertise `a=rtcp-mux`
    // (RFC 5761) and allocates a single far port — even though A's offer was NOT muxed.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "mux-offer".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false), // A did NOT offer mux
                profile: mux_profile("offer"),
            },
        )
        .await;
    let far_sdp = ok_sdp_text(&offer);
    assert!(
        far_sdp.contains("a=rtcp-mux"),
        "offer directive forces a=rtcp-mux on the far SDP: {far_sdp}"
    );
    assert!(
        !far_sdp.contains("a=rtcp:"),
        "no companion a=rtcp port under forced mux: {far_sdp}"
    );
    let far = sdp::parse(&far_sdp).expect("far");
    assert!(far.rtcp_mux);
    assert_eq!(
        far.remote_rtcp, far.remote_rtp,
        "RTCP rides the far RTP port"
    );
}

#[tokio::test]
async fn rtcp_mux_demux_directive_keeps_near_muxed_but_splits_the_far_side() {
    // rtpengine `rtcp-mux: [demux]`: A offered mux; the engine presents SEPARATE RTCP to the far
    // side (2 far ports, `a=rtcp-mux` stripped from the far SDP) while the near side stays muxed.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "mux-demux".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true), // A offered mux
                profile: mux_profile("demux"),
            },
        )
        .await;
    let far_sdp = ok_sdp_text(&offer);
    assert!(
        !far_sdp.contains("a=rtcp-mux"),
        "demux strips a=rtcp-mux from the far SDP: {far_sdp}"
    );
    let far = sdp::parse(&far_sdp).expect("far");
    assert!(!far.rtcp_mux, "far side demuxed");
    assert_ne!(
        far.remote_rtcp, far.remote_rtp,
        "far side has a distinct RTCP port"
    );

    // The near (A-facing) answer still advertises mux (the near side was left as offered).
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "mux-demux".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false), // B answers non-muxed on its own two ports
                profile: mux_profile("demux"),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");
    assert!(near.rtcp_mux, "near side stays muxed toward A");
}

#[tokio::test]
async fn rtcp_mux_reject_directive_forces_two_ports_both_sides() {
    // rtpengine `rtcp-mux: [reject]`: no mux either side even though A offered it — 2 far ports,
    // `a=rtcp-mux` stripped from the generated SDP.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "mux-reject".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true), // A offered mux
                profile: mux_profile("reject"),
            },
        )
        .await;
    let far_sdp = ok_sdp_text(&offer);
    assert!(
        !far_sdp.contains("a=rtcp-mux"),
        "reject strips a=rtcp-mux: {far_sdp}"
    );
    let far = sdp::parse(&far_sdp).expect("far");
    assert!(!far.rtcp_mux);
    assert_ne!(far.remote_rtcp, far.remote_rtp, "far RTCP on its own port");

    // The near side is demuxed too: the answer to A carries no a=rtcp-mux and a distinct port.
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "mux-reject".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: mux_profile("reject"),
            },
        )
        .await;
    let near_sdp = ok_sdp_text(&answer);
    assert!(
        !near_sdp.contains("a=rtcp-mux"),
        "near side demuxed toward A: {near_sdp}"
    );
    let near = sdp::parse(&near_sdp).expect("near");
    assert!(!near.rtcp_mux);
    assert_ne!(near.remote_rtcp, near.remote_rtp);
}

#[tokio::test]
async fn answer_and_delete_unknown_call_error() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "nope".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 5000 RTP/AVP 0\r\n".into(),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(answer, CmdResult::Error { .. }));

    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "nope".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(delete, CmdResult::Error { .. }));
}

#[tokio::test]
async fn unsupported_command_reports_error() {
    // `authenticate` is handled by the control server, not the session engine, so the engine's
    // dispatcher reports it as unsupported and names it in the error. (SubscribeRequest is now a
    // wired SIPREC verb — see the subscribe_* tests below.)
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let result = engine
        .handle(
            CLIENT,
            Command::Authenticate {
                token: "s3cret".into(),
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert!(reason.contains("authenticate")),
        other => panic!("expected error, got {other:?}"),
    }
}

#[tokio::test]
async fn subscribe_request_on_a_passthrough_call_promotes_and_offers() {
    // A plain relay (same codec both sides) IS now subscribable: subscribe_request promotes it to
    // userspace and returns a send-only SDP offer advertising the source leg's codec (raw tee).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "fork-relay".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "fork-relay".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        !engine.media().is_media_call("fork-relay"),
        "starts as a plain relay"
    );
    let result = engine
        .handle(
            CLIENT,
            Command::SubscribeRequest {
                call_id: "fork-relay".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            },
        )
        .await;
    match result {
        CmdResult::Ok {
            sdp: Some(sdp),
            to_tag: Some(_),
            ..
        } => {
            assert!(
                sdp.contains("a=sendonly"),
                "send-only subscriber offer (RFC 3264)"
            );
            assert!(
                sdp.contains("PCMU"),
                "advertises the source leg's codec (RFC 4566)"
            );
        }
        other => panic!("expected an SDP offer, got {other:?}"),
    }
    assert!(
        engine.media().is_relay_call("fork-relay"),
        "the relay was promoted to userspace"
    );
}

/// Parse a libpcap byte stream into `(source, destination, udp_payload)` per record, unwrapping the
/// synthetic Ethernet(14) + IPv4(20) + UDP(8) framing. Test-only, IPv4-only.
fn pcap_records(bytes: &[u8]) -> Vec<(SocketAddr, SocketAddr, Vec<u8>)> {
    use std::net::Ipv4Addr;
    let mut records = Vec::new();
    let mut offset = 24; // skip the global header
    while offset + 16 <= bytes.len() {
        let incl_len =
            u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
        offset += 16;
        if offset + incl_len > bytes.len() || incl_len < 42 {
            break;
        }
        let frame = &bytes[offset..offset + incl_len];
        offset += incl_len;
        let ip = &frame[14..];
        let source_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dest_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        let udp = &ip[20..];
        let source_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dest_port = u16::from_be_bytes([udp[2], udp[3]]);
        records.push((
            SocketAddr::new(source_ip.into(), source_port),
            SocketAddr::new(dest_ip.into(), dest_port),
            udp[8..].to_vec(),
        ));
    }
    records
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_recording_promotes_a_relay_and_captures_both_legs_to_pcap() {
    // End-to-end: a plain PCMU relay is `start recording`'d → promoted to userspace → each leg's
    // RTP is captured verbatim into a `.pcap` (synthetic IP/UDP framing) → `stop recording` demotes
    // it back to the fast path. (docs/security-and-nat.md: the promoted relay re-enforces the gate.)
    use crate::srtp_bridge::run_redirect_dispatcher;
    let dir = tempfile::tempdir().expect("tempdir");
    let engine = Engine::new(UdpLoopbackDatapath::new());
    // Route redirected datagrams to the media actor (a promoted relay uses `Redirect`).
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "rec-e2e".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let far_rtp = sdp::parse(&ok_sdp_text(&offer)).expect("far").remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "rec-e2e".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let near_rtp = sdp::parse(&ok_sdp_text(&answer)).expect("near").remote_rtp;
    assert!(
        !engine.media().is_media_call("rec-e2e"),
        "starts as a plain relay"
    );

    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "rec-e2e".into(),
                from_tag: "tag-a".into(),
                recording_dir: Some(dir.path().to_string_lossy().into_owned()),
                format: None,
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
            },
        )
        .await;
    assert!(matches!(started, CmdResult::Ok { .. }), "recording started");
    assert!(
        engine.media().is_relay_call("rec-e2e"),
        "the relay was promoted to userspace for recording"
    );

    // Feed one datagram each way; the promoted relay still forwards, so a receipt on the peer
    // confirms the actor processed (and therefore captured) the packet.
    phone_a
        .send_to(&rtp(0x0A0A_0A0A), near_rtp)
        .await
        .expect("a send");
    let (data, _) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A), "A→B still relayed while recording");
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), far_rtp)
        .await
        .expect("b send");
    let (data, _) = recv(&phone_a).await;
    assert_eq!(data, rtp(0x0B0B_0B0B), "B→A still relayed while recording");

    // Poll the pcap until the drain task has framed both captured datagrams.
    let path = dir.path().join("rec-e2e.pcap");
    let mut bytes = Vec::new();
    for _ in 0..200 {
        if let Ok(read) = std::fs::read(&path) {
            if pcap_records(&read).len() >= 2 {
                bytes = read;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(&bytes[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "libpcap magic");
    let records = pcap_records(&bytes);
    assert_eq!(
        records.len(),
        2,
        "both captured datagrams framed to the pcap"
    );

    // A's datagram: source = A's phone, destination = the engine's near RTP socket, payload verbatim.
    let a_record = records
        .iter()
        .find(|(source, ..)| *source == addr_a)
        .expect("A's captured datagram");
    assert_eq!(
        a_record.1, near_rtp,
        "captured destination = engine near RTP"
    );
    assert_eq!(
        a_record.2,
        rtp(0x0A0A_0A0A),
        "A's RTP captured byte-for-byte"
    );
    let b_record = records
        .iter()
        .find(|(source, ..)| *source == addr_b)
        .expect("B's captured datagram");
    assert_eq!(b_record.1, far_rtp, "captured destination = engine far RTP");
    assert_eq!(
        b_record.2,
        rtp(0x0B0B_0B0B),
        "B's RTP captured byte-for-byte"
    );

    // Stop recording: the relay is demoted back to the in-kernel Forward fast path.
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "rec-e2e".into(),
                from_tag: "tag-a".into(),
                recording_id: None,
            },
        )
        .await;
    assert!(matches!(stopped, CmdResult::Ok { .. }), "recording stopped");
    assert!(
        !engine.media().is_relay_call("rec-e2e") && !engine.media().is_media_call("rec-e2e"),
        "the relay was demoted back to the fast path once recording stopped"
    );
}

#[tokio::test]
async fn start_recording_rejects_a_secure_call_and_unknown_call() {
    // A secure (SRTP-bridge) call's on-the-wire bytes are ciphertext, so a raw pcap of them is
    // useless — `start recording` must reject it (mirrors `subscribe_request`). An unknown call errors.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "savp-rec".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "savp-rec".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_answer_sdp(addr_b, &b_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let secure = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "savp-rec".into(),
                from_tag: "tag-a".into(),
                recording_dir: Some("/tmp".into()),
                format: None,
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
            },
        )
        .await;
    assert!(
        matches!(secure, CmdResult::Error { .. }),
        "recording a secure call is rejected"
    );

    let unknown = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "nope".into(),
                from_tag: "f".into(),
                recording_dir: Some("/tmp".into()),
                format: None,
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
            },
        )
        .await;
    assert!(
        matches!(unknown, CmdResult::Error { .. }),
        "unknown call ⇒ error"
    );
}

/// Offer + answer a plain PCMU relay (both sides same codec ⇒ passthrough), with a live redirect
/// dispatcher so a promoted relay's Redirect datagrams reach its actor. Returns the engine.
async fn plain_relay_engine(
    call_id: &str,
    addr_a: SocketAddr,
    addr_b: SocketAddr,
) -> Engine<UdpLoopbackDatapath> {
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    engine
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_dtmf_promotes_a_relay_and_unblock_demotes_it_back() {
    // `block DTMF` on a plain relay promotes it to userspace (so the actor can gate the
    // telephone-event PT); `unblock DTMF` with no other hold demotes it back to the fast path.
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let engine = plain_relay_engine("bd-1", addr_a, addr_b).await;
    assert!(
        !engine.media().is_media_call("bd-1"),
        "starts as a plain relay"
    );

    let blocked = engine
        .handle(
            CLIENT,
            Command::BlockDtmf {
                call_id: "bd-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(blocked, CmdResult::Ok { .. }), "block DTMF ok");
    assert!(
        engine.media().is_relay_call("bd-1"),
        "the relay was promoted to userspace for the DTMF block"
    );

    let unblocked = engine
        .handle(
            CLIENT,
            Command::UnblockDtmf {
                call_id: "bd-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(unblocked, CmdResult::Ok { .. }), "unblock DTMF ok");
    assert!(
        !engine.media().is_relay_call("bd-1") && !engine.media().is_media_call("bd-1"),
        "the relay was demoted back to the fast path once the DTMF block cleared"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_promotes_a_passthrough_reflects_audio_then_disable_demotes() {
    // A single-leg IVR/echo call is a plain passthrough relay. `echo enabled=true` must promote it
    // into a *processing* MediaCall (decode → re-encode) and loop the caller's audio straight back;
    // `echo enabled=false` releases the hold and demotes it to the in-kernel Forward fast path.
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
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "echo-1".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    // The engine's A-facing endpoint is advertised in the answer's returned SDP — A sends there.
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "echo-1".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&answer))
        .expect("engine near SDP")
        .remote_rtp;
    assert!(
        !engine.media().is_media_call("echo-1"),
        "starts as a plain in-kernel relay"
    );

    let enabled = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
                enabled: true,
            },
        )
        .await;
    assert!(
        matches!(enabled, CmdResult::Ok { .. }),
        "echo enabled ok, got {enabled:?}"
    );
    assert!(
        engine.media().is_transcoding_call("echo-1"),
        "the relay was promoted to a processing MediaCall (not relay-only)"
    );
    let endpoints = engine
        .media()
        .call_endpoints("echo-1")
        .expect("registered media call");
    assert_ne!(
        endpoints[0], endpoints[1],
        "a 2-leg (answered) echo builds both directions on distinct near/far endpoints"
    );

    // A speaks µ-law toward the engine; with echo on it must come straight back to A. Retry to
    // absorb the tiny window between the control being applied and the first packet routing in.
    let mut echoed = None;
    for sequence in 0..25u16 {
        phone_a
            .send_to(&ulaw_rtp_packet(sequence, 0x1111_2222, 0xFF), engine_near)
            .await
            .expect("a send");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            echoed = Some((buffer[..len].to_vec(), from));
            break;
        }
    }
    let (packet, from) = echoed.expect("phone A hears its own audio echoed back");
    assert_eq!(
        from, engine_near,
        "echo comes from the engine's A-facing port"
    );
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&packet).expect("parse echoed rtp");
    assert_eq!(
        parsed.payload_type, 0,
        "re-encoded in A's own codec (µ-law PT 0)"
    );
    // µ-law decode+encode is idempotent, so A hears exactly the bytes it sent.
    assert_eq!(
        parsed.payload,
        &[0xFFu8; 160][..],
        "ingress audio reflected back verbatim"
    );

    let disabled = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-1".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
                enabled: false,
            },
        )
        .await;
    assert!(
        matches!(disabled, CmdResult::Ok { .. }),
        "echo disabled ok, got {disabled:?}"
    );
    assert!(
        !engine.media().is_media_call("echo-1"),
        "demoted back to the in-kernel Forward fast path once echo cleared"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_promotes_an_offer_only_call_reflects_audio_then_disable_tears_down() {
    // A UAS IVR/echo answers the caller itself and never dials a B leg — so the call is `offer`ed
    // but never `answer`ed (`far_codec` is None). `echo enabled=true` must still promote it to a
    // *single-leg* processing MediaCall that decodes the caller's ingress and re-encodes it back out
    // the same near endpoint (no far direction); `echo enabled=false` tears the actor down.
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
    let (phone_a, addr_a) = phone().await;

    // Offer only — the SBC never answers (there is no far leg). The engine's A-facing endpoint is
    // advertised in the *offer's* returned SDP, so A sends there.
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "echo-solo".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&offered))
        .expect("engine near SDP")
        .remote_rtp;
    assert!(
        !engine.media().is_media_call("echo-solo"),
        "an offer-only call starts as a plain in-kernel relay (no media actor)"
    );

    let enabled = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-solo".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
                enabled: true,
            },
        )
        .await;
    assert!(
        matches!(enabled, CmdResult::Ok { .. }),
        "echo enabled ok on an offer-only call, got {enabled:?}"
    );
    assert!(
        engine.media().is_transcoding_call("echo-solo"),
        "the offer-only relay was promoted to a processing MediaCall"
    );
    // Single-leg: both directions face the caller on the *one* near endpoint (no far direction).
    let endpoints = engine
        .media()
        .call_endpoints("echo-solo")
        .expect("registered media call");
    assert_eq!(
        endpoints[0], endpoints[1],
        "a single-leg echo builds one direction on the near endpoint — no far direction"
    );

    // A speaks µ-law toward the engine; with echo on it must come straight back out the same port.
    // Retry to absorb the window between the control landing and the first packet routing in.
    let mut echoed = None;
    for sequence in 0..25u16 {
        phone_a
            .send_to(&ulaw_rtp_packet(sequence, 0x3333_4444, 0xAB), engine_near)
            .await
            .expect("a send");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            echoed = Some((buffer[..len].to_vec(), from));
            break;
        }
    }
    let (packet, from) = echoed.expect("phone A hears its own audio echoed back");
    assert_eq!(
        from, engine_near,
        "echo comes back from the engine's A-facing port"
    );
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&packet).expect("parse echoed rtp");
    assert_eq!(
        parsed.payload_type, 0,
        "re-encoded in the caller's own codec (µ-law PT 0)"
    );
    // µ-law decode+encode is idempotent, so A hears exactly the bytes it sent.
    assert_eq!(
        parsed.payload,
        &[0xABu8; 160][..],
        "ingress audio reflected back verbatim"
    );

    let disabled = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-solo".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
                enabled: false,
            },
        )
        .await;
    assert!(
        matches!(disabled, CmdResult::Ok { .. }),
        "echo disabled ok, got {disabled:?}"
    );
    assert!(
        !engine.media().is_media_call("echo-solo"),
        "the single-leg processing actor is torn down once echo clears"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_media_promotes_an_offer_only_call_and_plays_the_prompt() {
    // A UAS IVR offers but never answers (single-leg). A prompt must play on it *before* any echo,
    // so `play_media` promotes the offer-only relay into a processing MediaCall (the same promote
    // `echo` uses) and injects the prompt toward the caller. The play accepts immediately with a
    // `play_id`, and a `PlayFinished{Completed}` carrying that id arrives when the prompt drains.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    // Register the owner's event channel *before* the play so the promoted actor's PlayFinished
    // has somewhere to land (the actor's event sink is the owning client's channel).
    let events_rx = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;

    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "play-solo".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&offered))
        .expect("engine near SDP")
        .remote_rtp;
    assert!(
        !engine.media().is_media_call("play-solo"),
        "an offer-only call starts as a plain in-kernel relay (no media actor)"
    );

    // An 8 kHz mono prompt: 320 samples = 40 ms → 2 frames at 20 ms ptime.
    use siphon_rtp_media::fanout::MediaSink as _;
    let mut recorder = siphon_rtp_media::wav::WavRecorder::new(8000, 1);
    recorder.write_pcm(&[1000i16; 320]);
    let wav = recorder.into_wav();

    let accepted = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "play-solo".into(),
                from_tag: "tag-a".into(),
                source: PlayMediaSource::Blob { data: wav },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await;
    let play_id = match accepted {
        CmdResult::Ok {
            duration_ms: Some(40),
            play_id: Some(id),
            ..
        } => id,
        other => panic!("play accepts with a 40 ms duration and a play_id, got {other:?}"),
    };
    assert!(
        engine.media().is_transcoding_call("play-solo"),
        "the offer-only relay was promoted to a processing MediaCall by play_media"
    );

    // The prompt is injected toward the caller's signalled address, so A hears it out the engine's
    // A-facing port — no ingress needed (the playout clock drives it).
    let mut prompt = None;
    for _ in 0..25u16 {
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            prompt = Some((buffer[..len].to_vec(), from));
            break;
        }
    }
    let (packet, from) = prompt.expect("phone A hears the injected prompt");
    assert_eq!(
        from, engine_near,
        "prompt comes from the engine's A-facing port"
    );
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&packet).expect("parse prompt rtp");
    assert_eq!(
        parsed.payload_type, 0,
        "prompt encoded in A's own codec (µ-law PT 0)"
    );

    // The prompt drains a couple of ticks after the last frame → PlayFinished{Completed} for our
    // play_id. Skip any unrelated event (e.g. a periodic quality report) while waiting.
    let mut finished = None;
    for _ in 0..50u16 {
        match timeout(Duration::from_millis(200), events_rx.recv_async()).await {
            Ok(Ok(Event::PlayFinished {
                conference_id: None,
                call_id,
                play_id: id,
                reason,
                played_ms,
                ..
            })) => {
                assert_eq!(call_id, "play-solo");
                finished = Some((id, reason, played_ms));
                break;
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    let (id, reason, played_ms) =
        finished.expect("a PlayFinished event arrives when the prompt drains");
    assert_eq!(id, play_id, "the completion carries the accept's play_id");
    assert_eq!(reason, siphon_rtp_proto::PlayEndReason::Completed);
    assert_eq!(played_ms, Some(40), "the whole 40 ms prompt played");
}

/// Offer + `answer_local` a single-leg µ-law call and start a decoded recording on it — the
/// voicemail shape: one party, the engine as the far side, recording begun at a moment the
/// controller picks rather than at answer.
async fn voicemail_call(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    addr: SocketAddr,
) -> SocketAddr {
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr, true),
                profile: Default::default(),
            },
        )
        .await;
    sdp::parse(&ok_sdp_text(&answered))
        .expect("the engine's answer")
        .remote_rtp
}

/// Wait for the `recording_finished` event for `recording_id`, skipping anything else.
async fn next_recording_finished(
    events: &flume::Receiver<Event>,
) -> Option<(
    String,
    Option<String>,
    u64,
    siphon_rtp_proto::RecordingEndReason,
)> {
    for _ in 0..60u16 {
        match timeout(Duration::from_millis(200), events.recv_async()).await {
            Ok(Ok(Event::RecordingFinished {
                recording_id,
                path,
                duration_ms,
                reason,
                ..
            })) => return Some((recording_id, path, duration_ms, reason)),
            Ok(Ok(_)) => continue,
            _ => return None,
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_voicemail_records_the_caller_and_reports_the_finished_file() {
    // The whole P3 shape end to end: a single-leg `answer_local` call (which `record_call` cannot
    // reach at all — `promote_to_processing` hardcodes `record_path: None`), recording started at
    // runtime, decoded audio streamed to disk, and a completion event that arrives only once the
    // file is closed. A consumer that acts on the event must never read a half-written file.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone, addr) = phone().await;
    let engine_near = voicemail_call(&engine, "vm", addr).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "vm".into(),
                from_tag: "tag-a".into(),
                recording_dir: Some(dir.path().to_string_lossy().into_owned()),
                format: Some(siphon_rtp_proto::RecordingFormat::Wav),
                direction: Some(siphon_rtp_proto::RecordingDirection::Ingress),
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
            },
        )
        .await;
    let recording_id = match started {
        CmdResult::Ok {
            recording_id: Some(id),
            ..
        } => id,
        other => panic!("a wav recording accepts with a recording_id, got {other:?}"),
    };

    // The caller speaks: ten µ-law frames of a constant non-zero level.
    for sequence in 0..10u16 {
        phone
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x20), engine_near)
            .await
            .expect("caller send");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(80)).await;

    let stopped = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "vm".into(),
                from_tag: "tag-a".into(),
                recording_id: Some(recording_id.clone()),
            },
        )
        .await;
    assert!(
        matches!(stopped, CmdResult::Ok { .. }),
        "stop accepted: {stopped:?}"
    );

    let (finished_id, path, duration_ms, reason) = next_recording_finished(&events)
        .await
        .expect("a recording_finished event arrives");
    assert_eq!(finished_id, recording_id, "the event correlates by id");
    assert_eq!(reason, siphon_rtp_proto::RecordingEndReason::Stopped);
    assert!(duration_ms > 0, "the caller's audio was recorded");

    // The file the event names is closed, complete, and readable by the tree's own WAV reader.
    let path = path.expect("the event names the file");
    let bytes = std::fs::read(&path).expect("the file exists when the event arrives");
    let parsed = siphon_rtp_media::player::WavSource::parse(&bytes)
        .expect("the finished file is a valid WAV");
    assert_eq!(parsed.sample_rate_hz(), 8000, "µ-law decodes to 8 kHz PCM");
    assert_eq!(parsed.channels(), 1);
    assert!(
        parsed.samples().iter().any(|&sample| sample != 0),
        "the recording holds the caller's audio, not silence"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recording_is_finalized_when_the_call_ends_under_it() {
    // A caller hanging up is the *normal* way a voicemail message ends, so teardown has to
    // produce a finished, playable file and a `call_ended` completion — not a valid WAV declaring
    // zero samples, which is what aborting the writer task would leave.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone, addr) = phone().await;
    let engine_near = voicemail_call(&engine, "vm-hangup", addr).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "vm-hangup".into(),
                from_tag: "tag-a".into(),
                recording_dir: Some(dir.path().to_string_lossy().into_owned()),
                format: Some(siphon_rtp_proto::RecordingFormat::Wav),
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
            },
        )
        .await;
    assert!(matches!(
        started,
        CmdResult::Ok {
            recording_id: Some(_),
            ..
        }
    ));
    for sequence in 0..6u16 {
        phone
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0x20), engine_near)
            .await
            .expect("caller send");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    tokio::time::sleep(Duration::from_millis(60)).await;

    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "vm-hangup".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;

    let (_id, path, duration_ms, reason) = next_recording_finished(&events)
        .await
        .expect("teardown still produces a completion event");
    assert_eq!(reason, siphon_rtp_proto::RecordingEndReason::CallEnded);
    assert!(
        duration_ms > 0,
        "the audio recorded before the hangup is kept"
    );
    let bytes = std::fs::read(path.expect("path")).expect("read");
    let parsed = siphon_rtp_media::player::WavSource::parse(&bytes)
        .expect("a hangup still leaves a valid WAV");
    assert!(
        !parsed.samples().is_empty(),
        "the header was finalized, so the file declares the audio it holds"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_path_is_honoured_and_an_unknown_recording_id_is_refused() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let _events = engine.register_client(CLIENT);
    let (_phone, addr) = phone().await;
    let _ = voicemail_call(&engine, "vm-path", addr).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let wanted = dir.path().join("greeting-reply.wav");
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "vm-path".into(),
                from_tag: "tag-a".into(),
                recording_dir: None,
                format: Some(siphon_rtp_proto::RecordingFormat::Wav),
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: Some(wanted.to_string_lossy().into_owned()),
            },
        )
        .await;
    assert!(matches!(
        started,
        CmdResult::Ok {
            recording_id: Some(_),
            ..
        }
    ));
    assert!(
        wanted.exists(),
        "the recording opened exactly the file it was told to"
    );

    // A stop for an id that is not running is an error, not a hollow success — a controller that
    // believes it stopped a recording and did not has no way to notice.
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "vm-path".into(),
                from_tag: "tag-a".into(),
                recording_id: Some("rec-does-not-exist".into()),
            },
        )
        .await;
    assert!(
        matches!(stopped, CmdResult::Error { .. }),
        "an unknown recording id is refused, got {stopped:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unwritable_recording_path_fails_the_verb_with_the_call_untouched() {
    // The file is opened before anything is promoted or attached, so a provisioning mistake is a
    // clean error on the verb rather than a `RecordingFinished{Error}` minutes later for a
    // recording the controller believes is running.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let _ = voicemail_call(&engine, "vm-bad-path", addr).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let unwritable = dir.path().join("no-such-directory").join("message.wav");

    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "vm-bad-path".into(),
                from_tag: "tag-a".into(),
                recording_dir: None,
                format: Some(siphon_rtp_proto::RecordingFormat::Wav),
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: Some(unwritable.to_string_lossy().into_owned()),
            },
        )
        .await;
    match started {
        CmdResult::Error { reason } => assert!(
            reason.contains("open"),
            "the refusal names the path problem, got: {reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(
        engine.recordings.is_empty(),
        "no recording was registered for a start that failed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pcap_recording_is_unchanged_by_the_wav_form() {
    // `format` absent must still mean pcap, byte for byte what it meant before — an existing
    // controller (and the whole NG front-end) sends exactly this.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "pcap-default".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "pcap-default".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let dir = tempfile::tempdir().expect("tempdir");
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "pcap-default".into(),
                from_tag: "tag-a".into(),
                recording_dir: Some(dir.path().to_string_lossy().into_owned()),
                format: None,
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
            },
        )
        .await;
    assert!(
        matches!(
            started,
            CmdResult::Ok {
                recording_id: None,
                ..
            }
        ),
        "a pcap recording carries no recording_id, got {started:?}"
    );
    assert!(
        dir.path().join("pcap-default.pcap").exists(),
        "the pcap landed at its historical path"
    );
    assert!(
        engine.media().is_relay_call("pcap-default"),
        "a pcap recording still takes the relay-only hold, not a processing one"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_endless_hold_bed_accepts_with_no_duration_and_keeps_playing_until_stopped() {
    // Music on hold, end to end. The accept must carry **no** `duration_ms` — there is none to
    // report — and the bed must still be playing long after a finite prompt of the same length
    // would have drained, ending only when the controller stops it.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events_rx = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "hold-bed".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;

    // A 40 ms bed: two frames at a 20 ms ptime, so a finite play would be over almost at once.
    use siphon_rtp_media::fanout::MediaSink as _;
    let mut recorder = siphon_rtp_media::wav::WavRecorder::new(8000, 1);
    recorder.write_pcm(&[1000i16; 320]);
    let wav = recorder.into_wav();

    let accepted = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "hold-bed".into(),
                from_tag: "tag-a".into(),
                source: PlayMediaSource::Blob { data: wav },
                repeat_times: Some(PlayRepeat::Forever),
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await;
    let play_id = match accepted {
        CmdResult::Ok {
            duration_ms,
            play_id: Some(id),
            ..
        } => {
            assert_eq!(
                duration_ms, None,
                "an endless bed has no duration to promise"
            );
            id
        }
        other => panic!("an endless play accepts with a play_id, got {other:?}"),
    };

    // Well past the 40 ms the body is long: still producing audio, and no PlayFinished.
    let mut frames = 0u32;
    for _ in 0..8u16 {
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
        {
            assert!(
                siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).is_ok(),
                "the bed keeps emitting well-formed RTP"
            );
            frames += 1;
        }
    }
    assert!(
        frames >= 4,
        "the bed looped well past its own 40 ms body, got {frames} frames"
    );
    assert!(
        events_rx.try_recv().is_err(),
        "an endless bed does not finish on its own"
    );

    // It ends when, and only when, the controller says so.
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopMedia {
                call_id: "hold-bed".into(),
                from_tag: "tag-a".into(),
                play_id: Some(play_id),
            },
        )
        .await;
    assert!(
        matches!(stopped, CmdResult::Ok { .. }),
        "stop accepted: {stopped:?}"
    );
    let mut finished = None;
    for _ in 0..50u16 {
        match timeout(Duration::from_millis(200), events_rx.recv_async()).await {
            Ok(Ok(Event::PlayFinished {
                play_id: id,
                reason,
                ..
            })) => {
                finished = Some((id, reason));
                break;
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    assert_eq!(
        finished,
        Some((play_id, siphon_rtp_proto::PlayEndReason::Stopped)),
        "the endless bed ends as Stopped, never as Completed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_duration_cap_still_bounds_an_endless_prompt() {
    // The cap is the one bound on an endless source short of a stop, and it must report the cap
    // as the accepted duration rather than nothing — the same answer a capped `*inf` tone gives.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "capped-bed".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    use siphon_rtp_media::fanout::MediaSink as _;
    let mut recorder = siphon_rtp_media::wav::WavRecorder::new(8000, 1);
    recorder.write_pcm(&[1000i16; 320]);
    let accepted = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "capped-bed".into(),
                from_tag: "tag-a".into(),
                source: PlayMediaSource::Blob {
                    data: recorder.into_wav(),
                },
                repeat_times: Some(PlayRepeat::Forever),
                start_pos_ms: None,
                duration_ms: Some(45_000),
                overlay: true,
                gain_decibels: Some(-12),
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(
            accepted,
            CmdResult::Ok {
                duration_ms: Some(45_000),
                play_id: Some(_),
                ..
            }
        ),
        "a capped endless bed reports the cap, got {accepted:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prompt_played_to_many_callers_is_decoded_once() {
    // The queue case: thirty waiting callers on one hold bed used to be thirty file reads, thirty
    // RIFF parses and thirty downmixes — three allocations proportional to prompt length, per
    // call. Now it is one decode and one shared buffer.
    use siphon_rtp_media::fanout::MediaSink as _;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hold.wav");
    let mut recorder = siphon_rtp_media::wav::WavRecorder::new(8000, 1);
    recorder.write_pcm(&[1000i16; 800]);
    std::fs::write(&path, recorder.into_wav()).expect("write prompt");

    for index in 0..3u8 {
        let call_id = format!("queued-{index}");
        let (_phone, addr) = phone().await;
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: call_id.clone(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_for(addr, true),
                    profile: Default::default(),
                },
            )
            .await;
        let played = engine
            .handle(
                CLIENT,
                Command::PlayMedia {
                    call_id,
                    from_tag: "tag-a".into(),
                    source: PlayMediaSource::File {
                        path: path.to_string_lossy().into_owned(),
                    },
                    repeat_times: None,
                    start_pos_ms: None,
                    duration_ms: None,
                    overlay: false,
                    gain_decibels: None,
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(played, CmdResult::Ok { .. }),
            "caller {index} hears the bed: {played:?}"
        );
    }

    let (hits, misses) = engine.prompts().stats();
    assert_eq!(misses, 1, "the prompt was decoded exactly once");
    assert_eq!(hits, 2, "the other two plays read the cached samples");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mu_law_prompt_plays_end_to_end() {
    // Prompts exported from another system are very often G.711, and the reader used to refuse
    // them outright (`unsupported WAV format tag 7`) — so a perfectly playable file could not be
    // provisioned without converting it first.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("greeting-ulaw.wav");
    let payload = vec![0x20u8; 800];
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"RIFF");
    buffer.extend_from_slice(&0u32.to_le_bytes());
    buffer.extend_from_slice(b"WAVE");
    buffer.extend_from_slice(b"fmt ");
    buffer.extend_from_slice(&16u32.to_le_bytes());
    buffer.extend_from_slice(&7u16.to_le_bytes()); // mu-law
    buffer.extend_from_slice(&1u16.to_le_bytes());
    buffer.extend_from_slice(&8000u32.to_le_bytes());
    buffer.extend_from_slice(&8000u32.to_le_bytes());
    buffer.extend_from_slice(&1u16.to_le_bytes());
    buffer.extend_from_slice(&8u16.to_le_bytes());
    buffer.extend_from_slice(b"data");
    buffer.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buffer.extend_from_slice(&payload);
    std::fs::write(&path, &buffer).expect("write prompt");

    let (_phone, addr) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ulaw-prompt".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr, true),
                profile: Default::default(),
            },
        )
        .await;
    let played = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "ulaw-prompt".into(),
                from_tag: "tag-a".into(),
                source: PlayMediaSource::File {
                    path: path.to_string_lossy().into_owned(),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(
            played,
            CmdResult::Ok {
                duration_ms: Some(100),
                ..
            }
        ),
        "800 mu-law bytes at 8 kHz is 100 ms of audio, got {played:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn re_recording_a_prompt_is_picked_up_without_restarting_the_engine() {
    // An operator who re-records a greeting and keeps hearing the old one has no way to tell the
    // cache is why, so freshness is part of the key rather than an operational step.
    use siphon_rtp_media::fanout::MediaSink as _;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("greeting.wav");

    let play = |call_id: String, path: std::path::PathBuf| {
        let engine = &engine;
        async move {
            let (_phone, addr) = phone().await;
            engine
                .handle(
                    CLIENT,
                    Command::Offer {
                        call_id: call_id.clone(),
                        from_tag: "tag-a".into(),
                        sdp: sdp_for(addr, true),
                        profile: Default::default(),
                    },
                )
                .await;
            engine
                .handle(
                    CLIENT,
                    Command::PlayMedia {
                        call_id,
                        from_tag: "tag-a".into(),
                        source: PlayMediaSource::File {
                            path: path.to_string_lossy().into_owned(),
                        },
                        repeat_times: None,
                        start_pos_ms: None,
                        duration_ms: None,
                        overlay: false,
                        gain_decibels: None,
                        to_tag: None,
                    },
                )
                .await
        }
    };

    let mut short = siphon_rtp_media::wav::WavRecorder::new(8000, 1);
    short.write_pcm(&[500i16; 800]); // 100 ms
    std::fs::write(&path, short.into_wav()).expect("write");
    let first = play("greet-1".to_string(), path.clone()).await;
    assert!(matches!(
        first,
        CmdResult::Ok {
            duration_ms: Some(100),
            ..
        }
    ));

    let mut longer = siphon_rtp_media::wav::WavRecorder::new(8000, 1);
    longer.write_pcm(&[500i16; 1600]); // 200 ms
    std::fs::write(&path, longer.into_wav()).expect("rewrite");
    let second = play("greet-2".to_string(), path).await;
    assert!(
        matches!(
            second,
            CmdResult::Ok {
                duration_ms: Some(200),
                ..
            }
        ),
        "the re-recorded prompt is served, got {second:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlay_tone_playback_runs_end_to_end_through_the_control_plane() {
    // Every new control-plane surface on one call: an overlay tone start, a second overlay, a
    // gain retune, a `play_id`-targeted stop, and the four-slot cap. Proves each field reaches
    // the code that acts on it — a field parsed and dropped would pass none of these.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events_rx = engine.register_client(CLIENT);
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "overlay-call".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&offered))
        .expect("engine near SDP")
        .remote_rtp;

    /// One `play_media` overlay start with a tone source.
    fn overlay_tone(tone: &str, gain_decibels: i32, duration_ms: Option<u64>) -> Command {
        Command::PlayMedia {
            call_id: "overlay-call".into(),
            from_tag: "tag-a".into(),
            source: PlayMediaSource::Tone { tone: tone.into() },
            repeat_times: None,
            start_pos_ms: None,
            duration_ms,
            overlay: true,
            gain_decibels: Some(gain_decibels),
            to_tag: None,
        }
    }

    // A preset ringback overlay: accepted with a play_id and, being endless, no duration.
    let first = engine
        .handle(CLIENT, overlay_tone("ringback_eu", -6, None))
        .await;
    let first_id = match first {
        CmdResult::Ok {
            play_id: Some(id),
            duration_ms,
            ..
        } => {
            assert_eq!(
                duration_ms, None,
                "an endless tone with no cap reports no duration"
            );
            id
        }
        other => panic!("overlay accept expected, got {other:?}"),
    };
    assert!(
        engine.media().is_transcoding_call("overlay-call"),
        "the overlay promoted the offer-only relay into a processing MediaCall"
    );

    // A second overlay from an explicit cadence spec, this one capped: the cap is the duration.
    let second = engine
        .handle(
            CLIENT,
            overlay_tone("425/1000,0/4000*inf", -18, Some(2_000)),
        )
        .await;
    let second_id = match second {
        CmdResult::Ok {
            play_id: Some(id),
            duration_ms: Some(2_000),
            ..
        } => id,
        other => panic!("capped overlay accept expected, got {other:?}"),
    };
    assert_ne!(first_id, second_id, "each playback gets its own id");

    // The party hears the overlay even though nothing is flowing toward it yet.
    let mut heard = false;
    for _ in 0..25u16 {
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            assert_eq!(
                from, engine_near,
                "the overlay comes from the engine's port"
            );
            assert!(len > 12, "an RTP packet, not an empty datagram");
            heard = true;
            break;
        }
    }
    assert!(
        heard,
        "an overlay with no live audio still reaches the party"
    );

    // Retune the first overlay in flight; an id no playback holds is an error, not a hollow ok.
    let retuned = engine
        .handle(
            CLIENT,
            Command::SetPlayGain {
                call_id: "overlay-call".into(),
                from_tag: "tag-a".into(),
                play_id: first_id,
                gain_decibels: -20,
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(retuned, CmdResult::Ok { .. }), "gain accepted");
    let unknown = engine
        .handle(
            CLIENT,
            Command::SetPlayGain {
                call_id: "overlay-call".into(),
                from_tag: "tag-a".into(),
                play_id: 999_999,
                gain_decibels: 0,
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(unknown, CmdResult::Error { .. }),
        "an unknown play_id is an error, got {unknown:?}"
    );

    // Fill the remaining two slots, then prove the fifth is rejected.
    for _ in 0..2 {
        let filled = engine
            .handle(CLIENT, overlay_tone("busy_eu", -12, None))
            .await;
        assert!(matches!(filled, CmdResult::Ok { .. }), "slot accepted");
    }
    let over_cap = engine
        .handle(CLIENT, overlay_tone("busy_eu", -12, None))
        .await;
    match over_cap {
        CmdResult::Error { reason } => assert!(
            reason.contains("no free overlay slot"),
            "the over-cap rejection must name the cap, got {reason:?}"
        ),
        other => panic!("a fifth overlay must be rejected, got {other:?}"),
    }

    // Stop just the second overlay: it reports Stopped, the others keep running.
    let stopped = engine
        .handle(
            CLIENT,
            Command::StopMedia {
                call_id: "overlay-call".into(),
                from_tag: "tag-a".into(),
                play_id: Some(second_id),
            },
        )
        .await;
    assert!(matches!(stopped, CmdResult::Ok { .. }), "targeted stop ok");
    let mut finished = None;
    for _ in 0..40u16 {
        match timeout(Duration::from_millis(200), events_rx.recv_async()).await {
            Ok(Ok(Event::PlayFinished {
                play_id, reason, ..
            })) => {
                finished = Some((play_id, reason));
                break;
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    assert_eq!(
        finished,
        Some((second_id, siphon_rtp_proto::PlayEndReason::Stopped)),
        "only the stopped overlay reports, under its own play_id"
    );
    // A second stop of the same id finds nothing.
    let again = engine
        .handle(
            CLIENT,
            Command::StopMedia {
                call_id: "overlay-call".into(),
                from_tag: "tag-a".into(),
                play_id: Some(second_id),
            },
        )
        .await;
    assert!(
        matches!(again, CmdResult::Error { .. }),
        "stopping an id twice is an error, got {again:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_media_from_a_url_rejects_a_bad_scheme_before_it_accepts() {
    // A URL the engine will never fetch is a plain control error, not an accepted playback that
    // fails a second later — the controller learns immediately.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr_a) = phone().await;
    let _ = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "url-bad".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    for url in [
        "file:///etc/passwd",
        "ftp://example.invalid/p.wav",
        "not a url",
    ] {
        let result = engine
            .handle(
                CLIENT,
                Command::PlayMedia {
                    call_id: "url-bad".into(),
                    from_tag: "tag-a".into(),
                    source: PlayMediaSource::Http { url: url.into() },
                    repeat_times: None,
                    start_pos_ms: None,
                    duration_ms: None,
                    overlay: false,
                    gain_decibels: None,
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "{url} must be refused on accept, got {result:?}"
        );
    }
    assert_eq!(
        engine.pending_media_fetches(),
        0,
        "a refused URL must leave no pending fetch behind"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_media_from_a_url_that_never_answers_ends_with_play_finished_error() {
    // The requirement in one test: a fetch that hangs must never hang the leg. `play_media`
    // accepts immediately with a `play_id` and no duration (the length is not knowable yet), the
    // failure arrives asynchronously as `PlayFinished{Error}` under that id, and the call is
    // still alive afterwards.
    use crate::media_fetch::MediaFetchLimits;
    use std::sync::Arc as StdArc;

    // A loopback listener that accepts and never answers — the first-byte timeout's job.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let silent = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            std::thread::sleep(std::time::Duration::from_secs(3));
            drop(stream);
        }
    });

    let engine =
        Engine::new(UdpLoopbackDatapath::new()).with_media_fetch_limits(MediaFetchLimits {
            connect_timeout: std::time::Duration::from_millis(300),
            first_byte_timeout: std::time::Duration::from_millis(300),
            total_timeout: std::time::Duration::from_millis(1_000),
            max_body_bytes: 64 * 1024,
            max_redirects: 1,
            allow_hosts: StdArc::new(Vec::new()),
        });
    let events_rx = engine.register_client(CLIENT);
    let (_phone, addr_a) = phone().await;
    let _ = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "url-hang".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;

    let accepted = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "url-hang".into(),
                from_tag: "tag-a".into(),
                source: PlayMediaSource::Http {
                    url: format!("http://{silent}/prompt.wav"),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await;
    let play_id = match accepted {
        CmdResult::Ok {
            play_id: Some(id),
            duration_ms: None,
            ..
        } => id,
        other => panic!("a URL play accepts with a play_id and no duration, got {other:?}"),
    };

    let mut finished = None;
    // Up to 8 s of polling: the fetch's own bounds fire in well under one, but a loaded CI box
    // must not turn a real pass into a flake. An elapsed poll is "not yet", not "never".
    for _ in 0..40u16 {
        match timeout(Duration::from_millis(200), events_rx.recv_async()).await {
            Ok(Ok(Event::PlayFinished {
                play_id: id,
                reason,
                call_id,
                ..
            })) => {
                assert_eq!(call_id, "url-hang");
                finished = Some((id, reason));
                break;
            }
            Ok(Ok(_)) => continue,
            // The control channel closed — nothing more will arrive.
            Ok(Err(_)) => break,
            // No event in this slice; the fetch is still running its bounds down.
            Err(_) => continue,
        }
    }
    assert_eq!(
        finished,
        Some((play_id, siphon_rtp_proto::PlayEndReason::Error)),
        "a fetch that never answers resolves the playback as an error"
    );
    assert!(
        engine.owned_call(CLIENT, "url-hang", |_| ()).is_some(),
        "the leg survives a failed prompt fetch"
    );
    assert_eq!(
        engine.pending_media_fetches(),
        0,
        "a finished fetch removes its own pending entry"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_a_url_playback_before_its_fetch_lands_cancels_it() {
    // Between the accept and the fetch there is a window where the controller holds a `play_id`
    // for something the media actor has never heard of. A stop in that window must cancel, not
    // be ignored and then play seconds later.
    use crate::media_fetch::MediaFetchLimits;
    use std::sync::Arc as StdArc;

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let silent = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            std::thread::sleep(std::time::Duration::from_secs(3));
            drop(stream);
        }
    });

    let engine =
        Engine::new(UdpLoopbackDatapath::new()).with_media_fetch_limits(MediaFetchLimits {
            connect_timeout: std::time::Duration::from_millis(800),
            first_byte_timeout: std::time::Duration::from_millis(2_000),
            total_timeout: std::time::Duration::from_millis(2_500),
            max_body_bytes: 64 * 1024,
            max_redirects: 1,
            allow_hosts: StdArc::new(Vec::new()),
        });
    let events_rx = engine.register_client(CLIENT);
    let (_phone, addr_a) = phone().await;
    let _ = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "url-stop".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let accepted = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "url-stop".into(),
                from_tag: "tag-a".into(),
                source: PlayMediaSource::Http {
                    url: format!("http://{silent}/slow.wav"),
                },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await;
    let play_id = match accepted {
        CmdResult::Ok {
            play_id: Some(id), ..
        } => id,
        other => panic!("expected an accept, got {other:?}"),
    };
    assert_eq!(engine.pending_media_fetches(), 1, "the fetch is in flight");

    let stopped = engine
        .handle(
            CLIENT,
            Command::StopMedia {
                call_id: "url-stop".into(),
                from_tag: "tag-a".into(),
                play_id: Some(play_id),
            },
        )
        .await;
    assert!(
        matches!(stopped, CmdResult::Ok { .. }),
        "stopping an in-flight fetch is accepted, got {stopped:?}"
    );
    assert_eq!(engine.pending_media_fetches(), 0, "the fetch was cancelled");
    let event = timeout(Duration::from_millis(500), events_rx.recv_async())
        .await
        .expect("an event arrives")
        .expect("channel open");
    assert_eq!(
        event,
        Event::PlayFinished {
            conference_id: None,
            call_id: "url-stop".into(),
            from_tag: "tag-a".into(),
            to_tag: None,
            play_id,
            reason: siphon_rtp_proto::PlayEndReason::Stopped,
            played_ms: Some(0),
        },
        "the cancelled fetch reports Stopped under its own play_id"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_media_rejects_a_malformed_tone_spec() {
    // The tone string is controller-supplied and untrusted: a malformed one is a clean control
    // error, never a panic and never a silently-started playback.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr_a) = phone().await;
    let _ = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "bad-tone".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    for tone in ["", "425", "425/0", "9000/100", "not_a_preset", "425/100*0"] {
        let result = engine
            .handle(
                CLIENT,
                Command::PlayMedia {
                    call_id: "bad-tone".into(),
                    from_tag: "tag-a".into(),
                    source: PlayMediaSource::Tone { tone: tone.into() },
                    repeat_times: None,
                    start_pos_ms: None,
                    duration_ms: None,
                    overlay: false,
                    gain_decibels: None,
                    to_tag: None,
                },
            )
            .await;
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "tone {tone:?} must be rejected, got {result:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn play_media_on_an_unknown_call_returns_an_error() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let result = engine
        .handle(
            CLIENT,
            Command::PlayMedia {
                call_id: "no-such-call".into(),
                from_tag: "tag-a".into(),
                source: PlayMediaSource::Blob { data: vec![0u8; 4] },
                repeat_times: None,
                start_pos_ms: None,
                duration_ms: None,
                overlay: false,
                gain_decibels: None,
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(result, CmdResult::Error { .. }),
        "an unknown call fails on accept"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_single_leg_active_call_survives_timeout_but_silent_is_reaped() {
    // A single-leg echo runs on a *redirected* endpoint, whose ingress does not touch the datapath's
    // `last_seen` the way the in-kernel Forward relay does. The media actor must therefore stamp
    // activity on each gated-in packet, so an actively-echoing caller is not reaped mid-call — while
    // a caller that falls silent still times out (the acceptance criterion: `#`/hangup ends it, a
    // silent call is reaped).
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
    let (phone_a, addr_a) = phone().await;

    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "echo-idle".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let engine_near = sdp::parse(&ok_sdp_text(&offered))
        .expect("engine near SDP")
        .remote_rtp;
    let enabled = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-idle".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
                enabled: true,
            },
        )
        .await;
    assert!(matches!(enabled, CmdResult::Ok { .. }), "echo enabled ok");

    // Advance the logical clock to tick 10, then speak: the actor stamps activity at tick 10 when it
    // gates the packet in (proven by hearing the echo, which the same accepted packet produces).
    engine.datapath().advance_clock(10);
    let mut heard = false;
    for sequence in 0..25u16 {
        phone_a
            .send_to(&ulaw_rtp_packet(sequence, 0x5566_7788, 0x7F), engine_near)
            .await
            .expect("a send");
        let mut buffer = [0u8; 2048];
        if timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer))
            .await
            .is_ok_and(|result| result.is_ok())
        {
            heard = true;
            break;
        }
    }
    assert!(
        heard,
        "the active caller hears its echo (packet was gated in)"
    );

    // Tick 14: only 4 ticks since the stamp (< 5) → recent media keeps the active call alive.
    engine.datapath().advance_clock(4);
    assert!(
        engine.reap_idle(5, 0).await.is_empty(),
        "an actively-echoing call is not reaped"
    );
    assert!(
        engine.media().is_media_call("echo-idle"),
        "the single-leg echo actor is still up"
    );

    // Tick 20: 10 ticks of silence (>= 5) → the now-silent call times out and is reaped.
    engine.datapath().advance_clock(6);
    assert_eq!(
        engine.reap_idle(5, 0).await,
        vec!["echo-idle".to_string()],
        "a silent single-leg echo call is reaped"
    );
    assert!(!engine.media().is_media_call("echo-idle"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_on_an_offer_only_call_with_no_codec_errors() {
    // An `offer` that carried no usable audio codec leaves `near_codec` None, so there is nothing to
    // decode/re-encode — echo must error clearly rather than promote a codec-less reflect path.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    // An offer whose m= line advertises only a codec the engine has no decoder/encoder for. Use a
    // dynamic payload type with no rtpmap so no primary codec is resolved.
    let sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 99\r\n",
        ip = addr_a.ip(),
        port = addr_a.port()
    );
    let offered = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "echo-nocodec".into(),
                from_tag: "tag-a".into(),
                sdp,
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(offered, CmdResult::Ok { .. }),
        "offer accepted, got {offered:?}"
    );
    let rejected = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-nocodec".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
                enabled: true,
            },
        )
        .await;
    assert!(
        matches!(&rejected, CmdResult::Error { reason } if reason.contains("no negotiated codec")),
        "echo on a codec-less offer errors, got {rejected:?}"
    );
    assert!(
        !engine.media().is_media_call("echo-nocodec"),
        "a codec-less call is never promoted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_on_a_transcoding_call_works_and_does_not_demote_it() {
    // A genuine transcode call (PCMU ↔ PCMA) already has a processing actor; echo must engage on it
    // as-is (no double-promote) and, when disabled, must NOT demote it — a transcode call has no
    // in-kernel Forward rules to fall back to (`relay_flows` is empty), so it stays in userspace.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "echo-tc".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"), // PCMU primary
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "echo-tc".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_with_conn(addr_b.ip(), addr_b.port(), 8, "PCMA"), // PCMA ⇒ transcode
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        engine.media().is_transcoding_call("echo-tc"),
        "PCMU↔PCMA answered as a transcode call"
    );

    let enabled = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-tc".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
                enabled: true,
            },
        )
        .await;
    assert!(matches!(enabled, CmdResult::Ok { .. }), "echo enabled ok");
    assert!(
        engine.media().is_transcoding_call("echo-tc"),
        "still the same transcode call — not double-promoted"
    );

    let disabled = engine
        .handle(
            CLIENT,
            Command::Echo {
                call_id: "echo-tc".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
                enabled: false,
            },
        )
        .await;
    assert!(matches!(disabled, CmdResult::Ok { .. }), "echo disabled ok");
    assert!(
        engine.media().is_transcoding_call("echo-tc"),
        "a genuine transcode call is never demoted when echo clears"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_from_a_non_owner_is_rejected_and_leaves_the_call_untouched() {
    // Only the owning client may control a call (docs §5). A non-owner gets `unknown call` and the
    // relay is left on the fast path — echo never promotes a call for a client that does not own it.
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let engine = plain_relay_engine("echo-own", addr_a, addr_b).await;

    let rejected = engine
        .handle(
            ClientId(2), // not the owner (CLIENT == ClientId(1))
            Command::Echo {
                call_id: "echo-own".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
                enabled: true,
            },
        )
        .await;
    assert!(
        matches!(rejected, CmdResult::Error { reason } if reason.contains("unknown call")),
        "a non-owning client gets unknown_call"
    );
    assert!(
        !engine.media().is_media_call("echo-own"),
        "the call was not promoted for a non-owner"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recording_and_block_dtmf_reason_set_holds_the_relay_until_both_release() {
    // The whole point of the promotion reason set: on one relay, start recording AND block DTMF;
    // releasing only one keeps the call promoted; releasing both demotes it back to the fast path.
    let dir = tempfile::tempdir().expect("tempdir");
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let engine = plain_relay_engine("bd-2", addr_a, addr_b).await;

    engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "bd-2".into(),
                from_tag: "tag-a".into(),
                recording_dir: Some(dir.path().to_string_lossy().into_owned()),
                format: None,
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::BlockDtmf {
                call_id: "bd-2".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        engine.media().is_relay_call("bd-2"),
        "promoted while both recording and DTMF-block hold it"
    );

    // Release only the DTMF block: still held up by the recording.
    engine
        .handle(
            CLIENT,
            Command::UnblockDtmf {
                call_id: "bd-2".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        engine.media().is_relay_call("bd-2"),
        "still promoted — the recording hold remains"
    );

    // Release the recording too: now nothing holds it, so it demotes back.
    engine
        .handle(
            CLIENT,
            Command::StopRecording {
                call_id: "bd-2".into(),
                from_tag: "tag-a".into(),
                recording_id: None,
            },
        )
        .await;
    assert!(
        !engine.media().is_relay_call("bd-2") && !engine.media().is_media_call("bd-2"),
        "demoted once both the recording and the DTMF-block holds cleared"
    );
}

#[tokio::test]
async fn block_dtmf_rejects_a_secure_call_and_unknown_call() {
    // A plain SRTP-bridge call's DTMF is ciphertext on the wire, not clear telephone-events, so
    // `block DTMF` must reject it (same guard as recording / subscribe_request). Unknown ⇒ error.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "bd-savp".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    transport_protocol: Some("RTP/SAVP".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "bd-savp".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: savp_answer_sdp(addr_b, &b_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let secure = engine
        .handle(
            CLIENT,
            Command::BlockDtmf {
                call_id: "bd-savp".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(secure, CmdResult::Error { .. }),
        "block DTMF on a secure (SRTP) call is rejected"
    );

    let unknown = engine
        .handle(
            CLIENT,
            Command::BlockDtmf {
                call_id: "nope".into(),
                from_tag: "f".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(unknown, CmdResult::Error { .. }),
        "unknown call ⇒ error"
    );
}

#[tokio::test]
async fn subscribe_request_on_an_unknown_call_is_unknown() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let result = engine
        .handle(
            CLIENT,
            Command::SubscribeRequest {
                call_id: "nope".into(),
                from_tags: vec!["f".into()],
                sdp: None,
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(result, CmdResult::Error { .. }),
        "unknown call ⇒ error"
    );
}

#[tokio::test]
async fn stop_media_on_unknown_call_errors() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let result = engine
        .handle(
            CLIENT,
            Command::StopMedia {
                call_id: "nope".into(),
                from_tag: "f".into(),
                play_id: None,
            },
        )
        .await;
    assert!(
        matches!(result, CmdResult::Error { .. }),
        "unknown call ⇒ error"
    );
}

/// A test phone bound to a specific loopback address, so the engine's signalled-source gate can
/// be exercised with distinct peers (127.0.0.0/8 is all loopback on Linux).
async fn phone_at(ip: Ipv4Addr) -> (UdpSocket, SocketAddr) {
    let socket = UdpSocket::bind((ip, 0)).await.expect("bind");
    let addr = socket.local_addr().expect("addr");
    (socket, addr)
}

/// A minimal RTP packet (V=2, PT=0/PCMU) carrying `ssrc` (RFC 3550 §5.1).
fn rtp(ssrc: u32) -> Vec<u8> {
    let mut packet = vec![0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    packet.extend_from_slice(&ssrc.to_be_bytes());
    packet.extend_from_slice(b"audio");
    packet
}

/// A plaintext `RTP/AVP` offer at a fixed RFC 5737 TEST-NET-3 address. The offer control path
/// never sends media, so no live socket is needed — only a parseable SDP body.
fn plain_offer_sdp() -> &'static str {
    concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 203.0.113.7\r\n",
        "s=-\r\n",
        "c=IN IP4 203.0.113.7\r\n",
        "t=0 0\r\n",
        "m=audio 30000 RTP/AVP 0 8\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
    )
}

/// A plaintext offer that additionally carries ICE (`a=ice-ufrag`/`a=ice-pwd`/`a=candidate`),
/// used to prove `ice: remove` strips the peer's ICE.
fn plain_ice_offer_sdp() -> &'static str {
    concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 203.0.113.7\r\n",
        "s=-\r\n",
        "c=IN IP4 203.0.113.7\r\n",
        "t=0 0\r\n",
        "a=ice-ufrag:PEERUF\r\n",
        "a=ice-pwd:peerpassword01234567\r\n",
        "m=audio 30000 RTP/AVP 0 8\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=candidate:1 1 UDP 2130706431 203.0.113.7 30000 typ host\r\n",
    )
}

/// A DTLS-SRTP offer (`UDP/TLS/RTP/SAVPF`) carrying `a=setup`/`a=fingerprint`, used to prove
/// `dtls: off` downgrades the far leg to plaintext and strips the DTLS keying.
fn dtls_offer_sdp() -> &'static str {
    concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 203.0.113.7\r\n",
        "s=-\r\n",
        "c=IN IP4 203.0.113.7\r\n",
        "t=0 0\r\n",
        "m=audio 30000 UDP/TLS/RTP/SAVPF 0 8\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=setup:actpass\r\n",
        "a=fingerprint:sha-256 ",
        "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\r\n",
    )
}

/// Drive an `offer` with `profile` and return the rewritten far-offer SDP text.
async fn offer_far_sdp(sdp: &str, profile: ProfileFlags) -> String {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ice-dtls-profile".into(),
                from_tag: "tag-a".into(),
                sdp: sdp.to_string(),
                profile,
            },
        )
        .await;
    ok_sdp_text(&offer)
}

#[tokio::test]
async fn offer_dtls_off_downgrades_far_leg_to_plaintext() {
    // rtpengine DTLS=off (RFC 3264): a UDP/TLS far transport plus `dtls: off` yields plaintext
    // RTP/AVP with the offer's DTLS keying stripped — no `a=fingerprint`/`a=setup`.
    let far = offer_far_sdp(
        dtls_offer_sdp(),
        ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            dtls: Some("off".into()),
            ..Default::default()
        },
    )
    .await;
    assert!(far.contains("RTP/AVP"), "{far}");
    assert!(!far.contains("UDP/TLS"), "{far}");
    assert!(!far.contains("a=fingerprint"), "{far}");
    assert!(!far.contains("a=setup"), "{far}");
    let parsed = sdp::parse(&far).expect("parse far offer");
    assert!(!parsed.dtls, "far leg is plaintext");
    assert!(!parsed.secure, "far leg is not SAVP");
}

#[tokio::test]
async fn offer_dtls_passive_sets_setup_role() {
    // RFC 4145 §4 / RFC 5763 §5: `dtls: passive` makes the engine the DTLS server (a=setup:passive)
    // instead of the default offerer role `actpass`.
    let far = offer_far_sdp(
        plain_offer_sdp(),
        ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            dtls: Some("passive".into()),
            ..Default::default()
        },
    )
    .await;
    let parsed = sdp::parse(&far).expect("parse far offer");
    assert!(parsed.dtls, "far leg advertises DTLS-SRTP");
    assert_eq!(parsed.setup, Some(sdp::Setup::Passive), "{far}");
    assert!(parsed.fingerprint.is_some(), "engine fingerprint present");
}

#[tokio::test]
async fn offer_dtls_active_sets_setup_role() {
    // `dtls: active` makes the engine the DTLS client (a=setup:active).
    let far = offer_far_sdp(
        plain_offer_sdp(),
        ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            dtls: Some("active".into()),
            ..Default::default()
        },
    )
    .await;
    let parsed = sdp::parse(&far).expect("parse far offer");
    assert_eq!(parsed.setup, Some(sdp::Setup::Active), "{far}");
}

#[tokio::test]
async fn offer_ice_force_advertises_ice_on_non_ice_offer() {
    // rtpengine ICE=force (RFC 8445): the engine advertises ICE-lite even though the offer carried
    // none — its own `a=ice-ufrag`/`a=ice-pwd` + host candidate, not the peer's.
    let far = offer_far_sdp(
        plain_offer_sdp(),
        ProfileFlags {
            ice: Some("force".into()),
            ..Default::default()
        },
    )
    .await;
    assert!(far.contains("a=ice-lite"), "{far}");
    assert!(far.contains("a=ice-ufrag:"), "{far}");
    assert!(far.contains("a=ice-pwd:"), "{far}");
    assert!(far.contains("typ host"), "engine host candidate: {far}");
    let parsed = sdp::parse(&far).expect("parse far offer");
    assert!(parsed.is_ice(), "far offer carries ICE");
}

#[tokio::test]
async fn offer_ice_remove_strips_peer_ice_without_re_originating() {
    // rtpengine ICE=remove (RFC 8839 §5): strip the offerer's ICE and advertise none of our own.
    let far = offer_far_sdp(
        plain_ice_offer_sdp(),
        ProfileFlags {
            ice: Some("remove".into()),
            ..Default::default()
        },
    )
    .await;
    assert!(!far.contains("a=ice-ufrag"), "{far}");
    assert!(!far.contains("a=ice-pwd"), "{far}");
    assert!(!far.contains("a=candidate"), "{far}");
    assert!(!far.contains("PEERUF"), "peer ufrag stripped: {far}");
    assert!(!far.contains("a=ice-lite"), "nothing re-originated: {far}");
    let parsed = sdp::parse(&far).expect("parse far offer");
    assert!(!parsed.is_ice(), "far offer carries no ICE");
}

/// A DTLS-SRTP answer from B at `addr` advertising one codec, with `peer`'s fingerprint and the
/// `setup` role given — enough to drive the control path without running a handshake.
fn dtls_answer_sdp(
    addr: SocketAddr,
    payload_type: u8,
    name: &str,
    peer: &siphon_rtp_dtls::DtlsCertificate,
    setup: sdp::Setup,
) -> String {
    let fingerprint = peer.fingerprint();
    let fingerprint = sdp::Fingerprint {
        hash_function: fingerprint.hash_function,
        bytes: fingerprint.bytes,
    };
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF {pt}\r\na=rtpmap:{pt} {name}/8000\r\na=rtcp-mux\r\n\
             a=setup:{setup}\r\na={fingerprint}\r\n",
        ip = addr.ip(),
        port = addr.port(),
        pt = payload_type,
        setup = setup.token(),
        fingerprint = fingerprint.to_attribute_value(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transcoding_dtls_call_answers_a_with_its_own_codec() {
    // RFC 3264 §6: on a transcoding call each party is answered with the codec it will actually
    // receive. That held for the plaintext and SDES transcode pipelines but not the DTLS one, so a
    // WebRTC leg answering a different codec had its codec relayed back to A — which A never
    // offered, and never receives, because the engine transcodes.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let peer = siphon_rtp_dtls::DtlsCertificate::generate().expect("peer cert");
    offer_from_a(
        &engine,
        "dtls-xcode",
        sdp_single_codec(addr_a, 0, "PCMU"),
        ProfileFlags {
            transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
            ..Default::default()
        },
    )
    .await;
    let answered = answer_from_b(
        &engine,
        "dtls-xcode",
        dtls_answer_sdp(addr_b, 8, "PCMA", &peer, sdp::Setup::Active),
        ProfileFlags::default(),
    )
    .await;

    assert_eq!(
        engine.calls.get("dtls-xcode").map(|call| call.pipeline),
        Some(PipelineKind::DtlsMedia),
        "a codec mismatch on a DTLS far leg takes the media pipeline"
    );
    assert_eq!(
        answered.primary_codec().map(|codec| codec.encoding_name),
        Some("PCMU".to_string()),
        "A is answered with its own codec"
    );
    assert_eq!(answered.payload_types, vec![0], "and only that codec");
    assert!(
        !answered
            .rtpmaps
            .iter()
            .any(|map| map.encoding_name.eq_ignore_ascii_case("PCMA")),
        "B's codec is never leaked to A"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dtls_srtp_offer_answer_bridges_media_end_to_end() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use bytes::Bytes;
    use siphon_rtp_dtls::{handshake, DtlsCertificate, DtlsRole, DtlsTransport};
    use std::time::Duration;
    use tokio::time::timeout;

    // Full control-plane path: A offers plaintext + a DTLS far-leg profile, the engine advertises
    // its fingerprint to B, B answers with its own fingerprint, the engine stands up the DTLS
    // bridge, B completes the handshake, and B's SRTP is relayed to A as plaintext.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await; // plain caller A
    let peer_b = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind b"),
    );
    let addr_b = peer_b.local_addr().expect("addr b");

    // A offers plaintext; the profile requests a DTLS-SRTP far leg.
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtls-e2e".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
    assert!(offer_reply.dtls, "engine advertised UDP/TLS/RTP/SAVPF to B");
    assert_eq!(offer_reply.setup, Some(sdp::Setup::Actpass));
    let engine_fingerprint = offer_reply
        .fingerprint
        .clone()
        .expect("engine a=fingerprint");
    let engine_far = offer_reply.remote_rtp; // where B sends toward the engine

    // B answers DTLS with its own fingerprint and `setup:active` (so the engine is DTLS server).
    let peer_cert = DtlsCertificate::generate().expect("peer cert");
    let peer_fingerprint = peer_cert.fingerprint();
    let peer_hex = peer_fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
             a=setup:active\r\na=fingerprint:{hash} {peer_hex}\r\n",
        ip = addr_b.ip(),
        port = addr_b.port(),
        hash = peer_fingerprint.hash_function,
    );
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dtls-e2e".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: answer_sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(
        matches!(answer, CmdResult::Ok { .. }),
        "answer ok: {answer:?}"
    );

    // B drives its side of the DTLS handshake (client) against the engine's far endpoint.
    let (b_transport, b_channels) = DtlsTransport::new(addr_b, engine_far);
    let reader = {
        let socket = peer_b.clone();
        let inbound = b_channels.inbound;
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while let Ok((len, _)) = socket.recv_from(&mut buffer).await {
                if inbound
                    .send_async(Bytes::copy_from_slice(&buffer[..len]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    };
    let writer = {
        let socket = peer_b.clone();
        let outbound = b_channels.outbound;
        tokio::spawn(async move {
            while let Ok(record) = outbound.recv_async().await {
                if socket.send_to(&record, engine_far).await.is_err() {
                    break;
                }
            }
        })
    };
    let engine_fingerprint = siphon_rtp_dtls::Fingerprint::new(
        engine_fingerprint.hash_function,
        engine_fingerprint.bytes,
    );
    let mut peer_leg = timeout(
        Duration::from_secs(5),
        handshake(
            Arc::new(b_transport),
            &peer_cert,
            DtlsRole::Client,
            &engine_fingerprint,
        ),
    )
    .await
    .expect("handshake did not time out")
    .expect("peer handshake");
    reader.abort();
    writer.abort();

    // B → engine SRTP is decrypted and relayed to A as plaintext. Retry to absorb the tiny window
    // between B finishing and the engine installing its leg.
    let media = rtp(0x0B0B_0B0B);
    let mut sealed = Vec::new();
    let mut relayed = None;
    for _ in 0..25 {
        sealed.clear();
        peer_leg.protect(&media, &mut sealed).expect("peer protect");
        peer_b.send_to(&sealed, engine_far).await.expect("b send");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            relayed = Some(buffer[..len].to_vec());
            break;
        }
    }
    assert_eq!(
        relayed.expect("phone A received the relayed media"),
        media,
        "B's DTLS-SRTP media is decrypted and relayed to A"
    );
}

/// Drive a DTLS peer's client-side handshake against `engine_far` over `socket`, returning its
/// keyed `SecureLeg`. Factored out of the DTLS end-to-end tests, which otherwise repeat 40 lines
/// of transport pumping apiece.
async fn peer_dtls_handshake(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    engine_far: SocketAddr,
    peer_cert: &siphon_rtp_dtls::DtlsCertificate,
    engine_fingerprint: &sdp::Fingerprint,
) -> siphon_rtp_srtp::leg::SecureLeg {
    use bytes::Bytes;
    use siphon_rtp_dtls::{handshake, DtlsRole, DtlsTransport};
    use std::time::Duration;
    use tokio::time::timeout;

    let (transport, channels) = DtlsTransport::new(peer_addr, engine_far);
    let reader = {
        let socket = socket.clone();
        let inbound = channels.inbound;
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while let Ok((len, _)) = socket.recv_from(&mut buffer).await {
                if inbound
                    .send_async(Bytes::copy_from_slice(&buffer[..len]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    };
    let writer = {
        let socket = socket.clone();
        let outbound = channels.outbound;
        tokio::spawn(async move {
            while let Ok(record) = outbound.recv_async().await {
                if socket.send_to(&record, engine_far).await.is_err() {
                    break;
                }
            }
        })
    };
    let expected = siphon_rtp_dtls::Fingerprint::new(
        engine_fingerprint.hash_function.clone(),
        engine_fingerprint.bytes.clone(),
    );
    let leg = timeout(
        Duration::from_secs(5),
        handshake(Arc::new(transport), peer_cert, DtlsRole::Client, &expected),
    )
    .await
    .expect("handshake did not time out")
    .expect("peer handshake");
    // The pump only carries the handshake; stop it so the test owns the socket for media.
    reader.abort();
    writer.abort();
    leg
}

/// Like [`peer_dtls_handshake`], but the peer drives the **server** side — used where the engine
/// took the client role from the `a=setup` complement.
async fn peer_dtls_handshake_server(
    socket: Arc<UdpSocket>,
    peer_addr: SocketAddr,
    engine_far: SocketAddr,
    peer_cert: &siphon_rtp_dtls::DtlsCertificate,
    engine_fingerprint: &sdp::Fingerprint,
) -> siphon_rtp_srtp::leg::SecureLeg {
    use bytes::Bytes;
    use siphon_rtp_dtls::{handshake, DtlsRole, DtlsTransport};
    use std::time::Duration;
    use tokio::time::timeout;

    let (transport, channels) = DtlsTransport::new(peer_addr, engine_far);
    let reader = {
        let socket = socket.clone();
        let inbound = channels.inbound;
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while let Ok((len, _)) = socket.recv_from(&mut buffer).await {
                if inbound
                    .send_async(Bytes::copy_from_slice(&buffer[..len]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        })
    };
    let writer = {
        let socket = socket.clone();
        let outbound = channels.outbound;
        tokio::spawn(async move {
            while let Ok(record) = outbound.recv_async().await {
                if socket.send_to(&record, engine_far).await.is_err() {
                    break;
                }
            }
        })
    };
    let expected = siphon_rtp_dtls::Fingerprint::new(
        engine_fingerprint.hash_function.clone(),
        engine_fingerprint.bytes.clone(),
    );
    let leg = timeout(
        Duration::from_secs(5),
        handshake(Arc::new(transport), peer_cert, DtlsRole::Server, &expected),
    )
    .await
    .expect("handshake did not time out")
    .expect("peer handshake");
    reader.abort();
    writer.abort();
    leg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_leg_is_transcoded_to_a_plain_leg_with_a_different_codec_each_side() {
    // WP-R4's headline, and the thing a WebRTC leg could not do before: a DTLS-SRTP (WebRTC-shaped)
    // far leg whose codec differs from the plaintext near leg is carried by the **media pipeline**,
    // not relayed opaquely — so it is decoded, transcoded and re-encrypted. A offers PCMU, B
    // answers PCMA over UDP/TLS/RTP/SAVPF with rtcp-mux, and media is verified in BOTH directions
    // (each arriving in the *receiver's* codec, which is what proves a transcode actually ran).
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_dtls::DtlsCertificate;
    use std::time::Duration;
    use tokio::time::timeout;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let peer_b = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind b"),
    );
    let addr_b = peer_b.local_addr().expect("addr b");

    // A offers plaintext PCMU; the profile asks for a DTLS-SRTP far leg.
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dtls-transcode".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: ProfileFlags {
                    transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let offer_reply = sdp::parse(&ok_sdp_text(&offer)).expect("offer reply");
    let engine_fingerprint = offer_reply.fingerprint.clone().expect("engine fingerprint");
    let engine_far = offer_reply.remote_rtp;

    // B answers DTLS with PCMA — a *different* codec, which is what selects the media pipeline.
    let peer_cert = DtlsCertificate::generate().expect("peer cert");
    let peer_fingerprint = peer_cert.fingerprint();
    let peer_hex = peer_fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 8\r\na=rtpmap:8 PCMA/8000\r\na=rtcp-mux\r\n\
             a=setup:active\r\na=fingerprint:{hash} {peer_hex}\r\n",
        ip = addr_b.ip(),
        port = addr_b.port(),
        hash = peer_fingerprint.hash_function,
    );
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "dtls-transcode".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: answer_sdp,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answer, CmdResult::Ok { .. }), "answer: {answer:?}");
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    assert!(
        engine.media().is_media_call("dtls-transcode"),
        "a DTLS leg with a codec mismatch must run through the media pipeline, not the bridge"
    );

    // Before the handshake there is no key: A's media must be dropped, never forwarded to B in
    // the clear. (B cannot read it, and putting A's cleartext on the wire would be the leak.)
    for sequence in 0..5u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    let mut buffer = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(300), peer_b.recv_from(&mut buffer))
            .await
            .is_err(),
        "media before the DTLS handshake must be dropped, not leaked to the secure peer"
    );

    // Complete B's handshake; the engine keys the pipeline asynchronously.
    let mut peer_leg = peer_dtls_handshake(
        peer_b.clone(),
        addr_b,
        engine_far,
        &peer_cert,
        &engine_fingerprint,
    )
    .await;

    // A → B: plaintext PCMU in, SRTP out, decrypting to PCMA (payload type 8).
    let mut to_b = None;
    for sequence in 10..60u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), peer_b.recv_from(&mut buffer)).await
        {
            let mut plain = Vec::new();
            peer_leg
                .unprotect(&buffer[..len], &mut plain)
                .expect("B decrypts the engine's SRTP");
            to_b = Some(plain);
            break;
        }
    }
    let to_b = to_b.expect("B received transcoded, encrypted media from A");
    assert_eq!(
        to_b[1] & 0x7f,
        8,
        "A's PCMU was transcoded into B's negotiated PCMA before encryption"
    );

    // B → A: SRTP PCMA in, plaintext PCMU out.
    let mut to_a = None;
    for sequence in 100..150u16 {
        let mut sealed = Vec::new();
        peer_leg
            .protect(&g711_rtp(8, sequence, 0x0B0B_0B0B, 0xD5), &mut sealed)
            .expect("B protects");
        peer_b.send_to(&sealed, engine_far).await.expect("b send");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            to_a = Some(buffer[..len].to_vec());
            break;
        }
    }
    let to_a = to_a.expect("A received decrypted, transcoded media from B");
    assert_eq!(
        to_a[1] & 0x7f,
        0,
        "B's PCMA was decrypted and transcoded into A's negotiated PCMU"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_media_leg_can_be_ws_teed_but_a_dtls_bridge_leg_cannot() {
    // The second half of what WP-R4 unlocks: once a DTLS leg's media reaches the pipeline it is an
    // ordinary media call, so the post-decode fan-out works and a WS tee attaches. The plain DTLS
    // *bridge* (same codec both sides, no pipeline) still cannot be teed — it relays ciphertext it
    // never decodes — and must say so rather than attach a sink that would never fire.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_dtls::DtlsCertificate;

    async fn dtls_call(
        engine: &Engine<UdpLoopbackDatapath>,
        call_id: &str,
        answer_codec: (u8, &str),
    ) {
        let (_phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
        let peer_b = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind b");
        let addr_b = peer_b.local_addr().expect("addr b");
        engine
            .handle(
                CLIENT,
                Command::Offer {
                    call_id: call_id.into(),
                    from_tag: "tag-a".into(),
                    sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                    profile: ProfileFlags {
                        transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
                        ..Default::default()
                    },
                },
            )
            .await;
        let peer_cert = DtlsCertificate::generate().expect("peer cert");
        let peer_fingerprint = peer_cert.fingerprint();
        let peer_hex = peer_fingerprint
            .bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        let (payload_type, name) = answer_codec;
        let answer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
                 m=audio {port} UDP/TLS/RTP/SAVPF {payload_type}\r\n\
                 a=rtpmap:{payload_type} {name}/8000\r\na=rtcp-mux\r\n\
                 a=setup:active\r\na=fingerprint:{hash} {peer_hex}\r\n",
            ip = addr_b.ip(),
            port = addr_b.port(),
            hash = peer_fingerprint.hash_function,
        );
        let answer = engine
            .handle(
                CLIENT,
                Command::Answer {
                    call_id: call_id.into(),
                    from_tag: "tag-a".into(),
                    to_tag: "tag-b".into(),
                    sdp: answer_sdp,
                    profile: ProfileFlags::default(),
                },
            )
            .await;
        assert!(matches!(answer, CmdResult::Ok { .. }), "answer: {answer:?}");
    }

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    // PCMA answer against a PCMU offer → a codec mismatch → the media pipeline → teeable.
    dtls_call(&engine, "dtls-teeable", (8, "PCMA")).await;
    assert!(engine.media().is_media_call("dtls-teeable"));
    let (uri, frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "dtls-teeable".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
            },
        )
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "a transcoded DTLS leg must be teeable: {attached:?}"
    );
    expect_tee_start(&frames).await;

    // PCMU answer against a PCMU offer → same codec → the plain crypto bridge → not teeable.
    dtls_call(&engine, "dtls-bridged", (0, "PCMU")).await;
    assert!(
        !engine.media().is_media_call("dtls-bridged"),
        "a same-codec DTLS call stays on the cheaper crypto bridge"
    );
    let (uri, _frames) = tee_server().await;
    let refused = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "dtls-bridged".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
            },
        )
        .await;
    match refused {
        CmdResult::Error { reason } => assert!(
            reason.contains("ciphertext"),
            "expected the crypto-bridge refusal, got {reason}"
        ),
        other => panic!("expected an error, got {other:?}"),
    }
}

/// A WebRTC-shaped (`UDP/TLS/RTP/SAVPF`) conference offer from `addr`, with an `a=fingerprint` line
/// when `fingerprint` carries one.
fn dtls_conference_offer(
    addr: SocketAddr,
    fingerprint: Option<&siphon_rtp_dtls::Fingerprint>,
) -> String {
    let fingerprint_line = fingerprint.map_or_else(String::new, |fingerprint| {
        let hex = fingerprint
            .bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        format!("a=fingerprint:{} {hex}\r\n", fingerprint.hash_function)
    });
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
         m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
         a=setup:actpass\r\n{fingerprint_line}",
        ip = addr.ip(),
        port = addr.port(),
    )
}

/// Join a plain participant, proving the one-endpoint pool has a free port again.
async fn a_plain_seat_still_fits<D: Datapath + Clone + Send + 'static>(engine: &Engine<D>) {
    let (_phone, phone_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "dtls-refusal-room".into(),
                from_tag: "tag-plain".into(),
                sdp: sdp_for(phone_addr, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(
        matches!(joined, CmdResult::Ok { .. }),
        "the refused DTLS seat did not give its port back: {joined:?}"
    );
}

#[tokio::test]
async fn a_dtls_conference_offer_without_a_fingerprint_is_refused_and_frees_its_port() {
    // One endpoint in the pool, so the plain seat after the refusal can bind only if the refused seat
    // released its port.
    let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(1));
    let webrtc_addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 3), 40_000));
    let refused = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "dtls-refusal-room".into(),
                from_tag: "tag-webrtc".into(),
                sdp: dtls_conference_offer(webrtc_addr, None),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    match refused {
        CmdResult::Error { reason } => assert_eq!(
            reason,
            "conference_join: UDP/TLS/RTP/SAVPF offer without an a=fingerprint"
        ),
        other => panic!("a fingerprint-less DTLS seat must be refused, got {other:?}"),
    }
    a_plain_seat_still_fits(&engine).await;
}

#[tokio::test]
async fn a_dtls_conference_offer_to_an_engine_without_a_certificate_is_refused_and_frees_its_port()
{
    let mut engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(1));
    // An engine that could not generate its DTLS certificate (the OS RNG failed at start-up).
    engine.dtls_certificate = None;
    let peer_certificate = siphon_rtp_dtls::DtlsCertificate::generate().expect("peer certificate");
    let webrtc_addr = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 3), 40_000));
    let refused = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "dtls-refusal-room".into(),
                from_tag: "tag-webrtc".into(),
                sdp: dtls_conference_offer(webrtc_addr, Some(&peer_certificate.fingerprint())),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    match refused {
        CmdResult::Error { reason } => {
            assert_eq!(reason, "conference_join: engine has no DTLS certificate");
        }
        other => panic!("a DTLS seat on a certificate-less engine must be refused, got {other:?}"),
    }
    a_plain_seat_still_fits(&engine).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dtls_participant_joins_a_conference_and_is_mixed_once_its_handshake_keys_the_seat() {
    // The last WP-R4 acceptance criterion: `conference_join` used to refuse a DTLS leg outright.
    // Now the seat is taken **pending** — neither mixed nor sent to — and the RFC 5764 handshake
    // keys it, after which the participant hears the room as SRTP it can decrypt.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_dtls::DtlsCertificate;
    use std::time::Duration;
    use tokio::time::timeout;

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    // A plain participant to give the room something to mix.
    let (plain, plain_addr) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let plain_answer = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "dtls-room".into(),
                from_tag: "tag-plain".into(),
                sdp: sdp_for(plain_addr, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let plain_engine_addr = sdp::parse(&ok_sdp_text(&plain_answer))
        .expect("plain answer")
        .remote_rtp;

    // The WebRTC-shaped participant: UDP/TLS/RTP/SAVPF with a fingerprint, no ICE.
    let webrtc = Arc::new(
        UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 3), 0))
            .await
            .expect("bind webrtc"),
    );
    let webrtc_addr = webrtc.local_addr().expect("webrtc addr");
    let peer_cert = DtlsCertificate::generate().expect("peer cert");
    let peer_fingerprint = peer_cert.fingerprint();
    let peer_hex = peer_fingerprint
        .bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let offer = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
             a=setup:actpass\r\na=fingerprint:{hash} {peer_hex}\r\n",
        ip = webrtc_addr.ip(),
        port = webrtc_addr.port(),
        hash = peer_fingerprint.hash_function,
    );
    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "dtls-room".into(),
                from_tag: "tag-webrtc".into(),
                sdp: offer,
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(
        matches!(joined, CmdResult::Ok { .. }),
        "a DTLS conference leg must be seated, not refused: {joined:?}"
    );
    let answer = sdp::parse(&ok_sdp_text(&joined)).expect("dtls answer");
    assert!(answer.dtls, "the answer advertises UDP/TLS/RTP/SAVPF");
    let engine_fingerprint = answer.fingerprint.clone().expect("engine a=fingerprint");
    let engine_seat = answer.remote_rtp;

    // Before the handshake the seat is inert: the plain participant talking must produce nothing
    // toward the unkeyed WebRTC peer (the room mix would otherwise go out in the clear).
    for sequence in 0..15u16 {
        plain
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), plain_engine_addr)
            .await
            .expect("plain send");
    }
    // The seat *will* receive DTLS handshake records — the engine is driving the handshake on this
    // same muxed endpoint (RFC 7983 §7). What it must never receive is **media**: an RTP/SRTP
    // first byte (128..=191) before the leg is keyed would be the room mix going out in the clear.
    for _ in 0..12 {
        let mut buffer = [0u8; 2048];
        match timeout(Duration::from_millis(120), webrtc.recv_from(&mut buffer)).await {
            Ok(Ok((len, _))) if len > 0 => assert!(
                (20..=63).contains(&buffer[0]),
                "an unkeyed DTLS seat received a non-DTLS packet (first byte {}) — the room mix \
                     must not reach it before the handshake keys the leg",
                buffer[0]
            ),
            _ => break, // nothing more pending
        }
    }

    // Complete the handshake (the engine advertised actpass → our peer answered, so the engine is
    // the DTLS client here and the peer is the server side of the exchange).
    let mut peer_leg = peer_dtls_handshake_server(
        webrtc.clone(),
        webrtc_addr,
        engine_seat,
        &peer_cert,
        &engine_fingerprint,
    )
    .await;

    // Now the room reaches it, encrypted: keep the plain leg talking and decrypt what arrives.
    let mut mixed = None;
    for sequence in 100..400u16 {
        plain
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), plain_engine_addr)
            .await
            .expect("plain send");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(60), webrtc.recv_from(&mut buffer)).await
        {
            let mut plain_rtp = Vec::new();
            if peer_leg.unprotect(&buffer[..len], &mut plain_rtp).is_ok() {
                mixed = Some(plain_rtp);
                break;
            }
        }
    }
    let mixed = mixed.expect("the keyed DTLS seat receives the room mix as decryptable SRTP");
    assert_eq!(
        mixed[1] & 0x7f,
        0,
        "the mix reaches the seat in its negotiated PCMU"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_answer_gates_out_an_off_path_rtpbleed_source() {
    // End-to-end: the engine must install a signalled-source gate from the SDP, so an attacker
    // on another address cannot latch the media even if it sprays the port first.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "rtpbleed".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "rtpbleed".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

    // Attacker sprays the A-facing port first — gated out, never reaches B.
    attacker
        .send_to(&rtp(0xAAAA_AAAA), near.remote_rtp)
        .await
        .expect("attacker send");
    let mut scratch = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(150), phone_b.recv_from(&mut scratch))
            .await
            .is_err(),
        "off-path attacker must be gated out end-to-end (RTPBleed)"
    );

    // The signalled peer A flows to B.
    phone_a
        .send_to(&rtp(0x1234_5678), near.remote_rtp)
        .await
        .expect("peer send");
    let (data, from) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x1234_5678));
    assert_eq!(
        from, far.remote_rtp,
        "B sees media from the engine far-RTP port"
    );
}

/// A single-codec (PCMU) SDP whose `c=` connection address is `conn` but whose media port is
/// `port` — so the signalled source and the real socket can differ (the NAT case: a private `c=`
/// with media arriving from a public address). `codec_pt`/`codec_name` pick the audio codec.
fn sdp_with_conn(conn: IpAddr, port: u16, codec_pt: u8, codec_name: &str) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {conn}\r\ns=-\r\nc=IN IP4 {conn}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP {codec_pt}\r\na=rtpmap:{codec_pt} {codec_name}/8000\r\na=rtcp-mux\r\n",
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn received_from_tightens_the_near_leg_gate_to_the_public_source() {
    // The NAT case: A advertises a *private/documentation* `c=` (203.0.113.2) that its media will
    // never actually come from, but the SIP proxy tells us (`received-from`) the real public
    // source is 127.0.0.2. The engine must gate the near leg to 127.0.0.2 — a TIGHTER RTPBleed
    // gate than the unusable signalled address (docs/security-and-nat.md §4 layer 2), so A's real
    // media flows while an off-path attacker is dropped.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;

    // A's offer advertises the documentation address 203.0.113.2 (unusable), real port = phone_a.
    let offer_sdp = sdp_with_conn(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        addr_a.port(),
        0,
        "PCMU",
    );
    let profile = ProfileFlags {
        received_from: Some(addr_a.ip()), // the proxy-observed public source
        ..Default::default()
    };
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "recvfrom".into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile,
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "recvfrom".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

    // An attacker on 127.0.0.9 sprays A's port — gated out by the received-from-tightened gate.
    attacker
        .send_to(&rtp(0xAAAA_AAAA), near.remote_rtp)
        .await
        .expect("attacker send");
    let mut scratch = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(150), phone_b.recv_from(&mut scratch))
            .await
            .is_err(),
        "off-path source gated out even though it raced the port first"
    );

    // A's real media (from the received-from IP) flows to B.
    phone_a
        .send_to(&rtp(0x1234_5678), near.remote_rtp)
        .await
        .expect("peer send");
    let (data, _from) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x1234_5678), "received-from source flows through");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn received_from_also_aims_the_relay_at_the_public_source_before_the_latch() {
    // The gate half of `received-from` was already right; the destination half was not. A NATed UA
    // advertises a private `c=` it will never receive on, so until its own first packet moves the
    // latch the relay was aiming the *other* party's audio at an unroutable address — the whole
    // pre-latch window (~400 ms at 20 ms ptime on a call where the callee speaks first), leaving
    // the node as a source of RFC 1918 datagrams.
    //
    // Here B speaks first, which is exactly that window: nothing from A has arrived, so nothing has
    // latched, and B's media has to reach A on the strength of the hint alone.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;

    // A advertises the documentation address 203.0.113.2 (unusable) on its real media port; the
    // proxy tells us its media really comes from 127.0.0.2.
    let offer_sdp = sdp_with_conn(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        addr_a.port(),
        0,
        "PCMU",
    );
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "recvfrom-dst".into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile: ProfileFlags {
                    received_from: Some(addr_a.ip()),
                    ..Default::default()
                },
            },
        )
        .await;
    let far_addr = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "recvfrom-dst".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;

    // B speaks first. A has sent nothing, so no latch exists on the near leg.
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), far_addr)
        .await
        .expect("b send");
    let (data, _from) = recv(&phone_a).await;
    assert_eq!(
        data,
        rtp(0x0B0B_0B0B),
        "B's first packet reaches A on the received-from address, not the private c="
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn received_from_never_installs_the_private_address_as_a_destination() {
    // The same property stated on the installed rule rather than on the wire: no `Forward` action
    // this call installs may carry the unroutable `c=` as its out_dst — not the RTP one and not the
    // companion RTCP one. Asserted on the rules because that is what the datapath transmits from
    // until the latch moves it.
    let datapath = LatchLearningDatapath::new();
    let engine = Engine::new(datapath.clone());
    let (_phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_phone_b, addr_b) = phone().await;
    let private = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
    // No rtcp-mux, so the companion RTCP flows are installed and covered too.
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {private}\r\ns=-\r\nc=IN IP4 {private}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        port = addr_a.port(),
    );
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "recvfrom-rules".into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile: ProfileFlags {
                    received_from: Some(addr_a.ip()),
                    ..Default::default()
                },
            },
        )
        .await;
    let _ = datapath.take_installs();
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "recvfrom-rules".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;

    let installs = datapath.take_installs();
    let destinations: Vec<SocketAddr> = installs
        .iter()
        .filter_map(|(_, action)| match action {
            FlowAction::Forward(rule) => rule.out_dst,
            _ => None,
        })
        .collect();
    assert!(
        !destinations.is_empty(),
        "the answer installed relay flows: {installs:?}"
    );
    assert!(
        destinations.iter().all(|dst| dst.ip() != private),
        "no flow may aim at the unroutable signalled address: {destinations:?}"
    );
    // A's two ports are aimed at the received-from IP, keeping each signalled port.
    assert!(
        destinations
            .iter()
            .any(|dst| *dst == SocketAddr::new(addr_a.ip(), addr_a.port())),
        "A's RTP is aimed at the public source on its signalled port: {destinations:?}"
    );
    assert!(
        destinations
            .iter()
            .any(|dst| *dst == SocketAddr::new(addr_a.ip(), addr_a.port() + 1)),
        "A's companion RTCP likewise: {destinations:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn received_from_tightens_the_transcode_media_gate() {
    // The same override must reach the media (transcode) slow path's `accepted_source`: A offers
    // PCMU behind a documentation `c=`, B answers PCMA (⇒ transcode). The near direction gates on
    // the received-from IP, so an off-path source is dropped by the media actor, not just the
    // datapath Forward gate.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;

    // A advertises the documentation address 203.0.113.2 (unusable); its real media socket is
    // phone_a, and the proxy-observed public source is passed as received-from.
    let offer_sdp = sdp_with_conn(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        addr_a.port(),
        0,
        "PCMU",
    );
    let profile = ProfileFlags {
        received_from: Some(addr_a.ip()),
        ..Default::default()
    };
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "recvfrom-media".into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile,
            },
        )
        .await;
    // B answers PCMA only → near=PCMU, far=PCMA → transcode media path.
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "recvfrom-media".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

    // Off-path attacker → the media actor's accepted_source gate drops it (nothing reaches B).
    attacker
        .send_to(&g711_rtp(0, 1, 0xAAAA_AAAA, 0xFF), near.remote_rtp)
        .await
        .expect("attacker send");
    let mut scratch = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(200), phone_b.recv_from(&mut scratch))
            .await
            .is_err(),
        "off-path source gated out on the transcode media path too"
    );

    // A valid PCMU frame from the received-from source transcodes to PCMA and reaches B.
    phone_a
        .send_to(&g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF), near.remote_rtp)
        .await
        .expect("a send");
    let (data, _from) = recv(&phone_b).await;
    let parsed = siphon_rtp_media::rtp::RtpPacket::parse(&data).expect("parse");
    assert_eq!(parsed.payload_type, 8, "B receives PCMA (transcoded)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offer_fails_cleanly_when_port_pool_exhausted_and_frees_on_delete() {
    // A non-mux call needs four endpoints (RTP + RTCP per leg); cap the pool at exactly four.
    let engine = Engine::new(UdpLoopbackDatapath::with_max_endpoints(4));
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    let first = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "c1".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(first, CmdResult::Ok { .. }),
        "first offer fits the pool"
    );

    let second = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "c2".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(second, CmdResult::Error { .. }),
        "an exhausted pool is a clean error, not a host-FD blowout"
    );

    // Tearing down the first call frees its four ports; the second offer now fits.
    let delete = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "c1".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(delete, CmdResult::Ok { .. }));
    let retry = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "c2".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(retry, CmdResult::Ok { .. }),
        "freed pool admits the call"
    );
}

#[tokio::test]
async fn a_call_is_private_to_its_creating_client() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr) = phone().await;
    let owner = ClientId(10);
    let intruder = ClientId(20);

    let offer = engine
        .handle(
            owner,
            Command::Offer {
                call_id: "private".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }));

    // The intruder cannot see the call: both query and delete report it as unknown.
    let query = engine
        .handle(
            intruder,
            Command::Query {
                call_id: "private".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(query, CmdResult::Error { .. }),
        "non-owner query is rejected"
    );
    let delete = engine
        .handle(
            intruder,
            Command::Delete {
                call_id: "private".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(delete, CmdResult::Error { .. }),
        "non-owner delete is rejected"
    );

    // The intruder's delete did nothing — the owner still has its call.
    let owner_query = engine
        .handle(
            owner,
            Command::Query {
                call_id: "private".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        matches!(owner_query, CmdResult::Ok { .. }),
        "owner still sees its call"
    );
}

#[tokio::test]
async fn per_client_call_quota_is_enforced_and_freed_on_delete() {
    let engine = Engine::with_max_calls_per_client(UdpLoopbackDatapath::new(), 1);
    let client = ClientId(7);
    let (_a, addr_a) = phone().await;
    let (_b, addr_b) = phone().await;

    let first = engine
        .handle(
            client,
            Command::Offer {
                call_id: "q1".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(first, CmdResult::Ok { .. }));

    let second = engine
        .handle(
            client,
            Command::Offer {
                call_id: "q2".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(second, CmdResult::Error { .. }),
        "over quota is rejected"
    );

    // Freeing the first call returns the quota slot.
    let delete = engine
        .handle(
            client,
            Command::Delete {
                call_id: "q1".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(delete, CmdResult::Ok { .. }));
    let retry = engine
        .handle(
            client,
            Command::Offer {
                call_id: "q2".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(retry, CmdResult::Ok { .. }),
        "freed quota admits the call"
    );
}

/// Pull the call-ids out of a `list` result (sorted for a stable assertion — the registry is
/// unordered).
fn list_call_ids(result: &CmdResult) -> Vec<String> {
    match result {
        CmdResult::List { call_ids } => {
            let mut ids = call_ids.clone();
            ids.sort();
            ids
        }
        other => panic!("expected List, got {other:?}"),
    }
}

#[tokio::test]
async fn list_enumerates_the_callers_calls() {
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // 0 calls → an empty list.
    let empty = engine.handle(CLIENT, Command::List).await;
    assert_eq!(list_call_ids(&empty), Vec::<String>::new());

    // 1 call → that call-id.
    let (_a, addr_a) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "one".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    assert_eq!(
        list_call_ids(&engine.handle(CLIENT, Command::List).await),
        vec!["one".to_string()]
    );

    // N calls → all of them.
    let (_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "two".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    assert_eq!(
        list_call_ids(&engine.handle(CLIENT, Command::List).await),
        vec!["one".to_string(), "two".to_string()]
    );
}

#[tokio::test]
async fn list_is_scoped_to_the_owning_client() {
    // A call is invisible to clients that do not own it (A3 — docs §5); `list` honours the same
    // ownership gate as `query`/`delete`, so it never leaks another client's call-ids.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let owner = ClientId(10);
    let intruder = ClientId(20);
    let (_a, addr_a) = phone().await;
    engine
        .handle(
            owner,
            Command::Offer {
                call_id: "owned".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;

    assert_eq!(
        list_call_ids(&engine.handle(owner, Command::List).await),
        vec!["owned".to_string()],
        "owner sees its own call"
    );
    assert_eq!(
        list_call_ids(&engine.handle(intruder, Command::List).await),
        Vec::<String>::new(),
        "a non-owner sees none of the owner's calls"
    );
}

#[tokio::test]
async fn statistics_reports_global_counters_and_live_sessions() {
    let engine = Engine::new(UdpLoopbackDatapath::new());

    // Fresh engine → all counters zero, no live sessions.
    let fresh = engine.handle(CLIENT, Command::Statistics).await;
    assert_eq!(
        fresh,
        CmdResult::Statistics {
            statistics: EngineStatistics::default(),
        }
    );

    // One accepted offer bumps offers_total and the live sessions gauge.
    let (_a, addr_a) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "stat-call".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    // An error-producing command (unknown call delete) bumps control_errors_total.
    let _ = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "no-such-call".into(),
                from_tag: "a".into(),
                to_tag: None,
            },
        )
        .await;

    let CmdResult::Statistics { statistics } = engine.handle(CLIENT, Command::Statistics).await
    else {
        panic!("expected Statistics");
    };
    assert_eq!(statistics.offers_total, 1, "one offer accepted");
    assert_eq!(statistics.answers_total, 0);
    // The failed delete counts as an accepted delete attempt *and* a control error (handle
    // records the per-command total before dispatch, then the error on the error result).
    assert_eq!(statistics.deletes_total, 1, "delete attempt counted");
    assert_eq!(
        statistics.control_errors_total, 1,
        "the unknown-call delete errored"
    );
    assert_eq!(statistics.sessions, 1, "the offered call is live");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_calls_are_reaped_and_active_ones_survive() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "c".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    let _far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "c".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");
    assert_eq!(engine.session_count(), 1);

    // Advance to tick 4 (within the 5-tick window) and send media — stamps activity at tick 4.
    engine.datapath().advance_clock(4);
    phone_a
        .send_to(&rtp(0x1234_5678), near.remote_rtp)
        .await
        .expect("send");
    let _ = recv(&phone_b).await;

    // Tick 8: idle since the packet (tick 4) is 4 < 5 → recent media keeps the call alive.
    engine.datapath().advance_clock(4);
    assert!(
        engine.reap_idle(5, 0).await.is_empty(),
        "recent media defers reaping"
    );
    assert_eq!(engine.session_count(), 1);

    // Tick 13: idle since tick 4 is 9 >= 5 → the silent call is reaped and its ports freed.
    engine.datapath().advance_clock(5);
    assert_eq!(engine.reap_idle(5, 0).await, vec!["c".to_string()]);
    assert_eq!(engine.session_count(), 0);
}

/// `sdp_for` with a direction attribute appended — the one line that separates a held call from a
/// dead one (RFC 4566 §6).
fn sdp_with_direction(rtp: SocketAddr, direction: &str) -> String {
    format!("{}a={direction}\r\n", sdp_for(rtp, false))
}

/// Offer + answer a two-party call whose parties declare `offer_direction` / `answer_direction`.
async fn held_call(
    engine: &Engine<UdpLoopbackDatapath>,
    client: ClientId,
    call_id: &str,
    addr_a: SocketAddr,
    addr_b: SocketAddr,
    offer_direction: &str,
    answer_direction: &str,
) {
    engine
        .handle(
            client,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_direction(addr_a, offer_direction),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            client,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_with_direction(addr_b, answer_direction),
                profile: Default::default(),
            },
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_call_outlives_the_media_timeout_and_reaps_on_its_own_ceiling() {
    // The defect this closes: hold is the most common mid-call operation on a PBX and it is
    // precisely the state where both parties legitimately stop sending (RFC 3264 §8.4 lets a held
    // endpoint transmit nothing at all). Judged by "no packets from anyone", such a call was torn
    // down 30 s in, while the person was still holding the handset.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let client = ClientId(11);
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    held_call(
        &engine, client, "held", addr_a, addr_b, "sendonly", "recvonly",
    )
    .await;

    // Far past the media timeout, and not one packet has been sent by either party.
    engine.datapath().advance_clock(100);
    assert!(
        engine.reap_idle(5, 1000).await.is_empty(),
        "neither party is expected to send, so their silence is not a dead path"
    );
    assert_eq!(engine.session_count(), 1);

    // Past the held ceiling, it does end — a call abandoned on hold is still freed eventually.
    engine.datapath().advance_clock(1000);
    assert_eq!(engine.reap_idle(5, 1000).await, vec!["held".to_string()]);
    assert_eq!(engine.session_count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_shape_of_hold_is_recognised_and_an_active_call_is_not() {
    // The shapes RFC 3264 §8.4 defines for hold, plus the control. `sendonly`/`recvonly` counts as
    // held in *both* orientations: §8.4 lets the sending side send nothing, so the attribute pair
    // is what identifies the state, not which end wrote which half.
    for (offer_direction, answer_direction, held) in [
        ("inactive", "inactive", true),
        ("sendonly", "recvonly", true),
        ("recvonly", "sendonly", true),
        ("sendrecv", "inactive", true), // only one end holds; the call is still off two-way media
        ("sendrecv", "sendrecv", false),
    ] {
        let engine = Engine::new(UdpLoopbackDatapath::new());
        let client = ClientId(12);
        let (_phone_a, addr_a) = phone().await;
        let (_phone_b, addr_b) = phone().await;
        held_call(
            &engine,
            client,
            "c",
            addr_a,
            addr_b,
            offer_direction,
            answer_direction,
        )
        .await;

        engine.datapath().advance_clock(100);
        let reaped = engine.reap_idle(5, 0).await;
        assert_eq!(
            reaped.is_empty(),
            held,
            "offer a={offer_direction} / answer a={answer_direction}: held={held}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_call_never_ages_out_when_the_held_ceiling_is_disabled() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let client = ClientId(13);
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    held_call(
        &engine, client, "parked", addr_a, addr_b, "inactive", "inactive",
    )
    .await;

    engine.datapath().advance_clock(1_000_000);
    assert!(
        engine.reap_idle(5, 0).await.is_empty(),
        "`0` disables the held ceiling — such a call is freed by `delete` alone"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn taking_a_call_off_hold_re_arms_the_dead_path_timer() {
    // A re-offer restates the offering party's own direction, so the unhold must put the call back
    // under the short ceiling — otherwise a call that was ever held would keep the two-hour budget
    // for the rest of its life and a genuinely dead path after an unhold would never be reaped.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let client = ClientId(14);
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    held_call(
        &engine, client, "unhold", addr_a, addr_b, "sendonly", "recvonly",
    )
    .await;
    engine.datapath().advance_clock(100);
    assert!(engine.reap_idle(5, 1000).await.is_empty(), "still held");

    // A re-offers with `sendrecv` — the unhold. It carries no direction attribute at all, which is
    // exactly what RFC 4566 §6 says `sendrecv` means, so the absence has to re-arm too.
    let reoffer = engine
        .handle(
            client,
            Command::Reoffer {
                call_id: "unhold".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(reoffer, CmdResult::Ok { .. }),
        "the re-offer is accepted: {reoffer:?}"
    );
    engine
        .handle(
            client,
            Command::Answer {
                call_id: "unhold".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;

    engine.datapath().advance_clock(100);
    assert_eq!(
        engine.reap_idle(5, 1000).await,
        vec!["unhold".to_string()],
        "off hold and silent is a dead path again"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_leg_call_is_held_by_its_only_partys_own_direction() {
    // An `answer_local` call (IVR, announcement, voicemail) has no second party: the engine is the
    // far side, and its own egress is not something to time out on. So the caller's direction is
    // the whole question — a caller that holds the IVR sends nothing and must not be reaped.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let client = ClientId(15);
    let (_phone, addr) = phone().await;
    engine
        .handle(
            client,
            Command::AnswerLocal {
                call_id: "ivr-held".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_with_direction(addr, "inactive"),
                profile: Default::default(),
            },
        )
        .await;

    engine.datapath().advance_clock(100);
    assert!(
        engine.reap_idle(5, 1000).await.is_empty(),
        "the caller told us it would send nothing"
    );
    engine.datapath().advance_clock(1000);
    assert_eq!(
        engine.reap_idle(5, 1000).await,
        vec!["ivr-held".to_string()],
        "and the held ceiling still ends it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn music_on_hold_refreshes_a_held_calls_own_ceiling() {
    // A held call that *does* carry audio — the `sendonly` party streaming music on hold — is
    // demonstrably alive, so its ceiling restarts from the media rather than from call setup. The
    // held budget is a backstop against an abandoned call, not a cap on how long hold may last.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let client = ClientId(16);
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    held_call(
        &engine, client, "moh", addr_a, addr_b, "sendonly", "recvonly",
    )
    .await;
    let near_rtp = engine
        .calls
        .get("moh")
        .map(|call| call.near.rtp.local_addr)
        .expect("the call has a near leg");

    engine.datapath().advance_clock(8);
    phone_a
        .send_to(&rtp(0x9999_0000), near_rtp)
        .await
        .expect("send");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Tick 16: 8 since the music, under the 10-tick held ceiling.
    engine.datapath().advance_clock(8);
    assert!(
        engine.reap_idle(5, 10).await.is_empty(),
        "the hold music refreshed the ceiling"
    );

    engine.datapath().advance_clock(20);
    assert_eq!(
        engine.reap_idle(5, 10).await,
        vec!["moh".to_string()],
        "and once even the music stops, the held ceiling still ends it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reaped_event_names_which_rule_fired() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let client = ClientId(17);
    let events = engine.register_client(client);
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    held_call(
        &engine, client, "held", addr_a, addr_b, "inactive", "inactive",
    )
    .await;

    engine.datapath().advance_clock(20);
    assert_eq!(engine.reap_idle(5, 10).await, vec!["held".to_string()]);

    let mut reason = None;
    let mut cdr_reason = None;
    while let Ok(event) = events.try_recv() {
        match event {
            Event::MediaTimeout { reason: seen, .. } => reason = Some(seen),
            Event::CallSummary { reason: seen, .. } => cdr_reason = Some(seen),
            _ => {}
        }
    }
    assert_eq!(
        reason,
        Some(MediaTimeoutReason::HeldTooLong),
        "a controller can tell 'the path died' from 'held too long'"
    );
    assert_eq!(
        cdr_reason.as_deref(),
        Some("held_timeout"),
        "and the CDR records the same distinction"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reaping_pushes_a_media_timeout_event_to_the_owner() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let client = ClientId(3);
    let events = engine.register_client(client);
    let (_phone, addr) = phone().await;

    engine
        .handle(
            client,
            Command::Offer {
                call_id: "gone".into(),
                from_tag: "ft".into(),
                sdp: sdp_for(addr, false),
                profile: Default::default(),
            },
        )
        .await;

    engine.datapath().advance_clock(10);
    assert_eq!(engine.reap_idle(5, 0).await, vec!["gone".to_string()]);

    // Reaping pushes two events to the owner: the end-of-call `CallSummary` (CDR) and the
    // `MediaTimeout` dead-path signal SIPhon already relies on. Both must fire (additive).
    let mut got_summary = false;
    let mut got_timeout = false;
    while let Ok(event) = events.try_recv() {
        match event {
            Event::CallSummary {
                call_id, reason, ..
            } => {
                assert_eq!(call_id, "gone");
                assert_eq!(reason, "media_timeout");
                got_summary = true;
            }
            Event::MediaTimeout {
                call_id,
                from_tag,
                reason,
            } => {
                assert_eq!(call_id, "gone");
                assert_eq!(from_tag, "ft");
                assert_eq!(
                    reason,
                    MediaTimeoutReason::NoMedia,
                    "a sendrecv call that went quiet is a dead path, not a hold"
                );
                got_timeout = true;
            }
            other => panic!("unexpected event pushed on reap: {other:?}"),
        }
    }
    assert!(got_timeout, "the media-timeout event is still pushed");
    assert!(
        got_summary,
        "reaping also emits the end-of-call CallSummary"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ice_offer_advertises_lite_and_the_endpoint_answers_checks() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    // A offers ICE.
    let offer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             a=ice-ufrag:AAAAAA\r\na=ice-pwd:apasswordapasswordapas\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr_a.ip(),
        port = addr_a.port()
    );
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ice".into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    let offer_out = ok_sdp_text(&offer);
    assert!(
        offer_out.contains("a=ice-lite"),
        "engine offers ICE-lite to B"
    );
    // The engine's advertised credentials (the same identity it installs on the endpoints).
    let advertised = sdp::parse(&offer_out).expect("parse engine offer");
    let engine_ufrag = advertised.ice_ufrag.clone().expect("engine ufrag");
    let engine_pwd = advertised.ice_pwd.clone().expect("engine pwd");

    // B answers with plain RTP (non-ICE).
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ice".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let answer_out = ok_sdp_text(&answer);
    assert!(
        answer_out.contains("a=ice-lite"),
        "engine offers ICE-lite to A"
    );
    let near = sdp::parse(&answer_out).expect("parse engine answer");

    // A runs a valid connectivity check against the engine's A-facing endpoint, signed with the
    // engine's advertised password.
    let username = format!("{engine_ufrag}:AAAAAA");
    let check = siphon_rtp_stun::binding_request(&[7u8; 12], &username, engine_pwd.as_bytes());
    phone_a
        .send_to(&check, near.remote_rtp)
        .await
        .expect("send check");

    // The endpoint answers with a Binding success response we can verify with the engine pwd.
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(1), phone_a.recv_from(&mut buffer))
        .await
        .expect("no timeout")
        .expect("recv response");
    let response = siphon_rtp_stun::parse(&buffer[..len]).expect("parse response");
    assert_eq!(response.message_type, siphon_rtp_stun::BINDING_SUCCESS);
    assert!(siphon_rtp_stun::verify_message_integrity(
        &buffer[..len],
        engine_pwd.as_bytes()
    ));
}

// ---- RFC 8445 §5.1.1 candidate gathering (end-to-end over the real datapath) -----------------

/// A stand-in STUN server that reports `mapped` as the source it saw — a NAT the loopback test
/// network cannot otherwise produce (on loopback the real reflexive address *is* the base, which
/// the gatherer correctly prunes as redundant). Answers every Binding request it receives.
async fn fake_stun_server(mapped: SocketAddr) -> SocketAddr {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind stun server");
    let address = socket.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            let Ok(request) = siphon_rtp_stun::parse(&buffer[..len]) else {
                continue;
            };
            if !request.is_binding_request() {
                continue;
            }
            let response =
                siphon_rtp_stun::binding_success_response(&request.transaction_id, mapped, None);
            let _ = socket.send_to(&response, from).await;
        }
    });
    address
}

/// The `a=candidate` lines of an SDP, parsed.
fn candidates_of(sdp: &str) -> Vec<siphon_rtp_ice::Candidate> {
    sdp.lines()
        .filter(|line| line.starts_with("a=candidate:"))
        .map(|line| siphon_rtp_ice::Candidate::parse(line).expect("our own candidate parses"))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gathering_advertises_a_server_reflexive_candidate_from_a_stun_server() {
    // The end-to-end proof that gathering is wired, not just implemented: the engine probes the
    // configured STUN server from its own media endpoint, correlates the response through the
    // datapath's full-agent seam, and puts the resulting candidate in the SDP it hands the peer.
    let mapped: SocketAddr = "203.0.113.5:52000".parse().expect("addr");
    let stun_server = fake_stun_server(mapped).await;
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_stun_servers(vec![stun_server]);
    let (_phone_a, addr_a) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "gather".into(),
                from_tag: "a".into(),
                sdp: ice_offer_from(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let offer_out = ok_sdp_text(&offer);

    // The offer is not muxed, so the leg has an RTCP endpoint too and gathers for both components
    // (RFC 8445 §4.1.1.1): host + srflx for component 1 (RTP) and for component 2 (RTCP).
    let all = candidates_of(&offer_out);
    assert_eq!(all.len(), 4, "host + srflx per component: {offer_out}");
    let candidates: Vec<_> = all
        .iter()
        .filter(|candidate| candidate.component == 1)
        .cloned()
        .collect();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].kind, siphon_rtp_ice::CandidateKind::Host);
    assert!(
        all.iter().any(|candidate| candidate.component == 2
            && candidate.kind == siphon_rtp_ice::CandidateKind::Host),
        "a non-muxed leg advertises its RTCP component too"
    );

    let reflexive = &candidates[1];
    assert_eq!(
        reflexive.kind,
        siphon_rtp_ice::CandidateKind::ServerReflexive
    );
    assert_eq!(reflexive.address, mapped, "the address the server reported");
    assert_eq!(
        reflexive.related,
        Some(candidates[0].address),
        "RFC 8839 §5.1: raddr is the base it was discovered from"
    );
    assert!(
        reflexive.priority < candidates[0].priority,
        "srflx ranks below host (RFC 8445 §5.1.2.2)"
    );
    assert_ne!(
        reflexive.foundation, candidates[0].foundation,
        "different type and server ⇒ different foundation (RFC 8445 §5.1.1.3)"
    );
    assert!(
        offer_out.contains("a=end-of-candidates"),
        "the list is complete when the offer is written (RFC 8838 §14)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_stun_server_still_yields_a_usable_offer() {
    // Gathering runs on the control path, so it must be bounded: a STUN server that never answers
    // costs one deadline and a host-only candidate list — never a failed call.
    let dead = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let dead_addr = dead.local_addr().expect("addr");
    drop(dead); // nothing is listening on that port now
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_stun_servers(vec![dead_addr]);
    let (_phone_a, addr_a) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "dead-stun".into(),
                from_tag: "a".into(),
                sdp: ice_offer_from(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let offer_out = ok_sdp_text(&offer);
    let candidates = candidates_of(&offer_out);
    // Host only, one per component — no reflexive candidate, and no failure either.
    assert_eq!(candidates.len(), 2, "host only: {offer_out}");
    assert!(candidates
        .iter()
        .all(|candidate| candidate.kind == siphon_rtp_ice::CandidateKind::Host));
    assert_eq!(engine.session_count(), 1, "and the call was still set up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_only_gathering_adds_no_round_trip_and_no_candidate_change() {
    // The default deployment (no STUN server): exactly the one host candidate the engine has
    // always advertised, gathered without touching the network.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "host-only".into(),
                from_tag: "a".into(),
                sdp: ice_offer_from(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let candidates = candidates_of(&ok_sdp_text(&offer));
    // One host candidate per component — the offer is not muxed, so RTP and RTCP both get one.
    assert_eq!(candidates.len(), 2);
    assert!(candidates
        .iter()
        .all(|candidate| candidate.kind == siphon_rtp_ice::CandidateKind::Host));
    let rtp = &candidates[0];
    assert_eq!(rtp.component, 1);
    assert_eq!(rtp.priority, 2_130_706_431);
    // RFC 8445 §5.1.2.1: the RTCP component ranks exactly one below the RTP component.
    assert_eq!(candidates[1].component, 2);
    assert_eq!(candidates[1].priority, 2_130_706_430);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_muxed_leg_gathers_only_the_rtp_component() {
    // Under RFC 5761 rtcp-mux there is no second component to gather for.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let muxed = format!("{}a=rtcp-mux\r\n", ice_offer_from(addr_a));
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "muxed".into(),
                from_tag: "a".into(),
                sdp: muxed,
                profile: Default::default(),
            },
        )
        .await;
    let candidates = candidates_of(&ok_sdp_text(&offer));
    assert_eq!(candidates.len(), 1, "one component under mux");
    assert_eq!(candidates[0].component, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_ice_answer_clears_the_ice_gate_gathering_installed_on_the_far_leg() {
    // Regression guard for the gathering wiring: gathering installs the ICE responder on the far
    // endpoints at *offer* time (that is how it receives its own Binding responses). If B then
    // answers without ICE, leaving it there would arm the layer-4 gate — media only from a
    // STUN-validated source — on a leg that will never send a check, and B's media would be
    // dropped forever. The answer must clear it.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "mixed".into(),
                from_tag: "a".into(),
                sdp: ice_offer_from(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "mixed".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                // B answers plain RTP — no ICE at all.
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("parse answer");

    // B's media must reach A even though B never ran a connectivity check.
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), near.remote_rtcp)
        .await
        .ok();
    let far_rtp = engine
        .calls
        .get("mixed")
        .map(|call| call.far_leg().rtp.local_addr)
        .expect("call exists");
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), far_rtp)
        .await
        .expect("send from B");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(1), phone_a.recv_from(&mut buffer))
        .await
        .expect("B's media reaches A — the far leg is not ICE-gated")
        .expect("recv");
    assert_eq!(&buffer[..len], rtp(0x0B0B_0B0B).as_slice());
}

// ---- RFC 8838 trickle ------------------------------------------------------------------------

/// Stand up a full-ICE call and return its near RTP endpoint id.
async fn full_ice_call(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> EndpointId {
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .calls
        .get(call_id)
        .map(|call| call.near.rtp.id)
        .expect("call")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trickled_candidate_is_paired_and_checked() {
    // RFC 8838: a browser sends its offer immediately and streams candidates afterwards. Each one
    // has to enter the checklist and be probed, or the path it describes is never used.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let near_rtp = full_ice_call(&engine, "trickle").await;
    let before = engine
        .ice_agents
        .as_ref()
        .and_then(|agents| agents.checklist_len(near_rtp))
        .expect("an agent runs on the near leg");

    let result = engine
        .handle(
            CLIENT,
            Command::IceCandidate {
                call_id: "trickle".into(),
                from_tag: "a".into(),
                to_tag: None,
                candidates: vec![
                    "a=candidate:late 1 UDP 1694498815 127.0.0.1 45999 typ host".to_string()
                ],
                end_of_candidates: false,
            },
        )
        .await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");

    let after = engine
        .ice_agents
        .as_ref()
        .and_then(|agents| agents.checklist_len(near_rtp))
        .expect("agent");
    assert_eq!(after, before + 1, "the trickled candidate became a pair");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unusable_trickled_candidates_do_not_cost_the_usable_one() {
    // A browser mixes mDNS and cross-family candidates in with routable ones. Rejecting the batch
    // would throw away the candidate that actually works.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let near_rtp = full_ice_call(&engine, "mixed-trickle").await;
    let before = engine
        .ice_agents
        .as_ref()
        .and_then(|agents| agents.checklist_len(near_rtp))
        .expect("agent");

    let result = engine
        .handle(
            CLIENT,
            Command::IceCandidate {
                call_id: "mixed-trickle".into(),
                from_tag: "a".into(),
                to_tag: None,
                candidates: vec![
                    // mDNS — unresolvable.
                    "a=candidate:m 1 UDP 2130706431 abc-def.local 5000 typ host".to_string(),
                    // Cross-family — cannot pair with a v4 leg.
                    "a=candidate:v6 1 UDP 2130706431 2001:db8::5 5000 typ host".to_string(),
                    // Garbage.
                    "a=candidate:broken 1 UDP zzz 127.0.0.1 5000 typ host".to_string(),
                    // The one that works.
                    "a=candidate:good 1 UDP 1694498815 127.0.0.1 46001 typ host".to_string(),
                ],
                end_of_candidates: true,
            },
        )
        .await;
    assert!(matches!(result, CmdResult::Ok { .. }), "{result:?}");
    assert_eq!(
        engine
            .ice_agents
            .as_ref()
            .and_then(|agents| agents.checklist_len(near_rtp))
            .expect("agent"),
        before + 1,
        "exactly the usable candidate was paired"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trickle_is_owner_only_and_needs_full_ice() {
    // Without a full agent there is no checklist to add to. Accepting and discarding would look
    // like it worked.
    let lite = Engine::new(UdpLoopbackDatapath::new());
    let _ = full_ice_call(&lite, "lite").await;
    let refused = lite
        .handle(
            CLIENT,
            Command::IceCandidate {
                call_id: "lite".into(),
                from_tag: "a".into(),
                to_tag: None,
                candidates: vec![
                    "a=candidate:x 1 UDP 1694498815 127.0.0.1 46002 typ host".to_string()
                ],
                end_of_candidates: false,
            },
        )
        .await;
    match refused {
        CmdResult::Error { reason } => assert!(reason.contains("full ICE"), "{reason}"),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // And another client cannot inject candidates into someone else's call.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let _ = full_ice_call(&engine, "owned-trickle").await;
    let intruder = engine
        .handle(
            ClientId(77),
            Command::IceCandidate {
                call_id: "owned-trickle".into(),
                from_tag: "a".into(),
                to_tag: None,
                candidates: vec![
                    "a=candidate:x 1 UDP 1694498815 127.0.0.1 46003 typ host".to_string()
                ],
                end_of_candidates: false,
            },
        )
        .await;
    assert!(matches!(intruder, CmdResult::Error { .. }));
}

// ---- re-offer + RFC 8445 §9 ICE restart ------------------------------------------------------

/// A re-offer from A carrying the given ICE credentials and its host candidate.
fn reoffer_sdp(addr: SocketAddr, ufrag: &str, pwd: &str) -> String {
    format!(
        "v=0\r\no=- 1 2 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             a=ice-ufrag:{ufrag}\r\na=ice-pwd:{pwd}\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=candidate:peer 1 UDP 2130706431 {ip} {port} typ host\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_keeps_the_media_ports_where_a_repeated_offer_would_move_them() {
    // The distinction the verb exists for. A repeated `Offer` replaces the call on fresh ports;
    // a `Reoffer` renegotiates in place, so the dialog's media path is undisturbed.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "re".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    // The re-offer is delivered to B, so the reference is the last SDP B received from the
    // engine: the original offer (RFC 3264 §8), not the answer A was sent.
    let before = sdp::parse(&ok_sdp_text(&offer)).expect("parse").remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "re".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let answered = sdp::parse(&ok_sdp_text(&answer)).expect("parse").remote_rtp;

    let reoffer = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "re".into(),
                from_tag: "a".into(),
                sdp: reoffer_sdp(addr_a, A_UFRAG, A_PWD),
                profile: Default::default(),
            },
        )
        .await;
    let after = sdp::parse(&ok_sdp_text(&reoffer))
        .expect("parse")
        .remote_rtp;

    assert_eq!(
        after, before,
        "the re-offer re-advertises the same far port B was offered"
    );
    assert_ne!(
        after, answered,
        "and never the near port, which is A's socket"
    );
    assert_eq!(
        engine.session_count(),
        1,
        "and does not create a second call"
    );

    // Media still relays across the renegotiation, with B sending where the re-offer told it.
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), after)
        .await
        .expect("send from B");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(1), phone_a.recv_from(&mut buffer))
        .await
        .expect("media survives the re-offer")
        .expect("recv");
    assert_eq!(&buffer[..len], rtp(0x0B0B_0B0B).as_slice());
}

/// An `m=audio` (PCMU) + plaintext RFC 4103 `m=text` (RED pt 98 wrapping T.140 pt 99) SDP — audio
/// and text on their own ports, sharing the loopback connection address.
fn audio_plaintext_text_sdp(audio: SocketAddr, text: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {aport} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             m=text {tport} RTP/AVP 98 99\r\na=rtpmap:98 red/1000\r\na=rtpmap:99 t140/1000\r\n",
        ip = audio.ip(),
        aport = audio.port(),
        tport = text.port(),
    )
}

/// The same, but a **secure** (SDES-SRTP) text stream: `RTP/SAVP` carrying the peer's own text
/// `a=crypto` (RFC 4568). Audio stays plaintext `RTP/AVP`.
fn audio_secure_text_sdp(
    audio: SocketAddr,
    text: SocketAddr,
    text_key: &CryptoAttribute,
) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {aport} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             m=text {tport} RTP/SAVP 98 99\r\na=rtpmap:98 red/1000\r\na=rtpmap:99 t140/1000\r\n\
             a={crypto}\r\n",
        ip = audio.ip(),
        aport = audio.port(),
        tport = text.port(),
        crypto = text_key.to_attribute_value(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_reanchors_a_plaintext_rfc4103_text_stream_to_the_engine_text_port() {
    // RFC 8839 §5.4 / RFC 4103: a re-offer re-advertises the SAME endpoints (ports do not move), so a
    // negotiated `m=text` stream MUST be re-anchored to the engine's existing text port — never passed
    // through pointing at the UE's own (often private) address, the exact leak the offer/answer path
    // already closes. The re-offer is delivered to B, so the port is the FAR text port B was offered.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a_audio, addr_a_audio) = phone().await;
    let (_phone_a_text, addr_a_text) = phone().await;
    let (_phone_b_audio, addr_b_audio) = phone().await;
    let (_phone_b_text, addr_b_text) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "rtt-reoffer".into(),
                from_tag: "a".into(),
                sdp: audio_plaintext_text_sdp(addr_a_audio, addr_a_text),
                profile: Default::default(),
            },
        )
        .await;
    // Ground truth: the engine's far text port, advertised to B in the offer.
    let engine_far_text = sdp::parse(&ok_sdp_text(&offer))
        .expect("parse offer")
        .text
        .expect("offer anchored an m=text")
        .remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "rtt-reoffer".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: audio_plaintext_text_sdp(addr_b_audio, addr_b_text),
                profile: Default::default(),
            },
        )
        .await;
    // The engine text port advertised back to A in the answer — A's socket, never shown to B.
    let engine_near_text = sdp::parse(&ok_sdp_text(&answer))
        .expect("parse answer")
        .text
        .expect("answer anchored an m=text")
        .remote_rtp;

    // A re-offers with its `m=text` still pointing at A's own (private) text address.
    let reoffer = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "rtt-reoffer".into(),
                from_tag: "a".into(),
                sdp: audio_plaintext_text_sdp(addr_a_audio, addr_a_text),
                profile: Default::default(),
            },
        )
        .await;
    let text = sdp::parse(&ok_sdp_text(&reoffer))
        .expect("parse reoffer")
        .text
        .expect("re-offer re-anchored the m=text");
    assert_eq!(
        text.remote_rtp, engine_far_text,
        "the re-offer re-anchors m=text to the engine's far text port, as the offer did"
    );
    assert_ne!(
        text.remote_rtp, engine_near_text,
        "and never presents B the near text port, which is A's"
    );
    assert_ne!(
        text.remote_rtp, addr_a_text,
        "and never re-advertises A's own (private) text address"
    );
    assert!(
        !text.secure,
        "a plaintext text stream stays RTP/AVP on the re-offer"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_reanchors_a_secure_text_stream_re_presenting_the_same_engine_crypto() {
    // RFC 8839 §5.4 / RFC 4568: a secure (SDES-SRTP) `m=text` re-offer re-anchors to the engine text
    // port AND re-advertises the engine's OWN stored text `a=crypto` — the same key the recipient
    // already holds, never a freshly minted one. The re-offer is delivered to B, so that is the FAR
    // text port and the far text key B was given at offer. The near key protects the engine's text
    // toward A: handing it to B would give B the key to A's stream.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a_audio, addr_a_audio) = phone().await;
    let (_phone_a_text, addr_a_text) = phone().await;
    let (_phone_b_audio, addr_b_audio) = phone().await;
    let (_phone_b_text, addr_b_text) = phone().await;

    // A and B each mint their OWN text SDES key (their leg's inbound key).
    let a_text_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen a");
    let b_text_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen b");

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "sec-rtt-reoffer".into(),
                from_tag: "a".into(),
                sdp: audio_secure_text_sdp(addr_a_audio, addr_a_text, &a_text_key),
                profile: Default::default(),
            },
        )
        .await;
    let offer_text = sdp::parse(&ok_sdp_text(&offer))
        .expect("parse offer")
        .text
        .expect("offer anchored a secure m=text");
    assert!(offer_text.secure, "the offer advertised RTP/SAVP text to B");
    let engine_far_text = offer_text.remote_rtp;
    let engine_far_text_key = offer_text
        .crypto
        .first()
        .copied()
        .expect("offer advertised the engine's far text a=crypto");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "sec-rtt-reoffer".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: audio_secure_text_sdp(addr_b_audio, addr_b_text, &b_text_key),
                profile: Default::default(),
            },
        )
        .await;
    let answer_text = sdp::parse(&ok_sdp_text(&answer))
        .expect("parse answer")
        .text
        .expect("answer anchored a secure m=text");
    assert!(answer_text.secure, "the answer advertised RTP/SAVP text");
    // The engine's own near text key advertised to A in the answer (never A's or B's).
    let engine_near_text = answer_text.remote_rtp;
    let engine_near_text_key = answer_text
        .crypto
        .first()
        .copied()
        .expect("answer advertised the engine's near text a=crypto");

    // A re-offers the secure text stream with its own key + private address again.
    let reoffer = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "sec-rtt-reoffer".into(),
                from_tag: "a".into(),
                sdp: audio_secure_text_sdp(addr_a_audio, addr_a_text, &a_text_key),
                profile: Default::default(),
            },
        )
        .await;
    let text = sdp::parse(&ok_sdp_text(&reoffer))
        .expect("parse reoffer")
        .text
        .expect("re-offer re-anchored the secure m=text");
    assert!(text.secure, "the re-offer re-advertises RTP/SAVP text");
    assert_eq!(
        text.remote_rtp, engine_far_text,
        "the re-offer re-anchors secure m=text to the engine's far text port"
    );
    assert_ne!(
        text.remote_rtp, engine_near_text,
        "and never presents B the near text port"
    );
    let reoffer_text_key = text
        .crypto
        .first()
        .copied()
        .expect("re-offer advertised a text a=crypto");
    assert_eq!(
        reoffer_text_key.key, engine_far_text_key.key,
        "the re-offer re-presents the SAME far text key B was offered, not a freshly minted one"
    );
    assert_ne!(
        reoffer_text_key.key, engine_near_text_key.key,
        "and never the near text key, which protects the engine's text toward A"
    );
    assert_ne!(
        reoffer_text_key.key, a_text_key.key,
        "and never forwards A's own key"
    );
    assert_ne!(reoffer_text_key.key, b_text_key.key, "nor B's");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_audio_only_reoffer_carries_no_text_section() {
    // The text re-anchor must not synthesize an `m=text` where the call negotiated none — an
    // audio-only re-offer is left exactly as the pre-text path handled it.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "audio-reoffer".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "audio-reoffer".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        engine
            .calls
            .get("audio-reoffer")
            .and_then(|call| call.near.text)
            .is_none(),
        "an audio-only call has no engine text endpoint"
    );

    let reoffer = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "audio-reoffer".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        sdp::parse(&ok_sdp_text(&reoffer))
            .expect("parse reoffer")
            .text
            .is_none(),
        "an audio-only re-offer carries no m=text section"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_peer_credentials_on_a_reoffer_restart_ice_with_fresh_local_ones() {
    // RFC 8445 §9.1.1.1: a restart is detected from new credentials, and the restarting agent
    // MUST advertise new ones of its own.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "restart".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    // What B was offered: the reference a re-offer delivered to B is judged against.
    let offered = sdp::parse(&ok_sdp_text(&offer)).expect("parse offer");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "restart".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let first = sdp::parse(&ok_sdp_text(&answer)).expect("parse");
    let first_ufrag = first.ice_ufrag.clone().expect("engine ufrag");

    // Same credentials again ⇒ not a restart: our own must not churn.
    let same = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "restart".into(),
                from_tag: "a".into(),
                sdp: reoffer_sdp(addr_a, A_UFRAG, A_PWD),
                profile: Default::default(),
            },
        )
        .await;
    assert_eq!(
        sdp::parse(&ok_sdp_text(&same))
            .expect("parse")
            .ice_ufrag
            .as_deref(),
        Some(first_ufrag.as_str()),
        "an unchanged re-offer is not a restart"
    );

    // New peer credentials ⇒ restart, and we mint new ones.
    let restarted = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "restart".into(),
                from_tag: "a".into(),
                sdp: reoffer_sdp(addr_a, "NEWUFRAG", "newpasswordnewpassword"),
                profile: Default::default(),
            },
        )
        .await;
    let restarted = sdp::parse(&ok_sdp_text(&restarted)).expect("parse");
    assert_ne!(
        restarted.ice_ufrag.as_deref(),
        Some(first_ufrag.as_str()),
        "a restart advertises fresh local credentials (RFC 8445 §9.1.1.1)"
    );
    assert!(restarted.ice_pwd.is_some());
    // The ports are unchanged even across a restart — that is what keeps media flowing. The
    // re-offer goes to B, so they are the far ports B was offered, candidates included.
    assert_eq!(restarted.remote_rtp, offered.remote_rtp);
    assert_ne!(restarted.remote_rtp, first.remote_rtp);
    assert_eq!(
        candidate_addresses(&restarted),
        candidate_addresses(&offered),
        "the restart re-presents the far leg's candidates, as the offer did"
    );
    // And the peer's new credentials are what the leg now expects.
    let stored = engine
        .calls
        .get("restart")
        .and_then(|call| call.near_remote_ice.clone())
        .expect("peer creds stored");
    assert_eq!(stored.ufrag, "NEWUFRAG");
    let _ = phone_a;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn media_keeps_flowing_on_the_old_pair_across_an_ice_restart() {
    // RFC 8445 §9.3: an agent keeps using the previously selected pair until the new session
    // completes. Concretely, the datapath's adopted source must survive the restart — if the
    // restart cleared it, every call would go silent for the length of a new ICE exchange.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "continuity".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "continuity".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let near_rtp = engine
        .calls
        .get("continuity")
        .map(|call| call.near.rtp.id)
        .expect("call");
    // Stand in for a completed ICE session: a pair has been selected and adopted.
    engine.datapath().adopt_source(near_rtp, addr_a);
    assert_eq!(
        engine.datapath().ice_validated_source(near_rtp),
        Some(addr_a)
    );

    engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "continuity".into(),
                from_tag: "a".into(),
                sdp: reoffer_sdp(addr_a, "NEWUFRAG", "newpasswordnewpassword"),
                profile: Default::default(),
            },
        )
        .await;

    assert_eq!(
        engine.datapath().ice_validated_source(near_rtp),
        Some(addr_a),
        "the previously selected pair is still adopted across the restart (§9.3)"
    );
    // Which means media really does keep moving while the new session runs.
    let far_rtp = engine
        .calls
        .get("continuity")
        .map(|call| call.far_leg().rtp.local_addr)
        .expect("call");
    phone_b
        .send_to(&rtp(0x0C0C_0C0C), far_rtp)
        .await
        .expect("send from B");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(1), phone_a.recv_from(&mut buffer))
        .await
        .expect("media does not stop for the restart")
        .expect("recv");
    assert_eq!(&buffer[..len], rtp(0x0C0C_0C0C).as_slice());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_is_owner_only_and_refuses_a_codec_change() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "guarded".into(),
                from_tag: "a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "guarded".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;

    // Another client cannot renegotiate someone else's call.
    let intruder = engine
        .handle(
            ClientId(99),
            Command::Reoffer {
                call_id: "guarded".into(),
                from_tag: "a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(intruder, CmdResult::Error { .. }));

    // Nor can the owner silently switch codec mid-call: rebuilding a live pipeline is not done
    // here, and answering "ok" while still running PCMU would be worse than refusing.
    let switched = engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: "guarded".into(),
                from_tag: "a".into(),
                sdp: sdp_single_codec(addr_a, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    match switched {
        CmdResult::Error { reason } => {
            assert!(reason.contains("codec"), "explains why: {reason}")
        }
        other => panic!("a codec change must be refused, got {other:?}"),
    }
}

// ---- a re-offer presents the leg facing the party it is delivered to -------------------------
//
// RFC 3264 §8: a re-offer modifies the SDP its *recipient* last received. The controller forwards
// the engine's rewritten re-offer to the other party, so the SDP must present the leg facing that
// party — the far leg for a re-offer from A, the near leg for one from B — exactly as the original
// offer and answer did. Every test below has the recipient act on the SDP it was actually sent,
// never on engine state, because that is the one thing a real peer does.

/// The `(component, address)` of every candidate an SDP carries, in order.
fn candidate_addresses(info: &sdp::MediaInfo) -> Vec<(u16, SocketAddr)> {
    info.candidates
        .iter()
        .map(|candidate| (candidate.component, candidate.address))
        .collect()
}

/// `offer` from A (tag `a`) and return the rewritten SDP delivered to B.
async fn offer_from_a(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    sdp: String,
    profile: ProfileFlags,
) -> sdp::MediaInfo {
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp,
                profile,
            },
        )
        .await;
    sdp::parse(&ok_sdp_text(&offer)).expect("parse the offer B receives")
}

/// `answer` from B (tags `a` → `b`) and return the rewritten SDP delivered to A.
async fn answer_from_b(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    sdp: String,
    profile: ProfileFlags,
) -> sdp::MediaInfo {
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp,
                profile,
            },
        )
        .await;
    sdp::parse(&ok_sdp_text(&answer)).expect("parse the answer A receives")
}

/// `reoffer` from the party whose tag is `tag`.
async fn reoffer_from(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    tag: &str,
    sdp: String,
    profile: ProfileFlags,
) -> CmdResult {
    engine
        .handle(
            CLIENT,
            Command::Reoffer {
                call_id: call_id.into(),
                from_tag: tag.into(),
                sdp,
                profile,
            },
        )
        .await
}

/// Assert nothing arrives on `socket` within a short window.
async fn assert_silent(socket: &UdpSocket, why: &str) {
    let mut scratch = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(150), socket.recv_from(&mut scratch))
            .await
            .is_err(),
        "{why}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_a_on_a_new_port_lets_b_reach_a_through_the_far_leg() {
    // A two-party plain relay. A moves its RTP port and re-offers the same session (RFC 3264 §8);
    // B answers the re-offer unchanged and starts sending where it was told. The engine used to
    // present the re-offer with the near leg — A's own socket — so B's media landed on A's leg
    // from an address that is not A's, the near source gate dropped all of it, and A heard
    // nothing for the rest of the call while B heard A fine.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a_before, addr_a_before) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;

    let offered = offer_from_a(
        &engine,
        "moved",
        sdp_for(addr_a_before, false),
        ProfileFlags::default(),
    )
    .await;
    let answered = answer_from_b(
        &engine,
        "moved",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;

    let reoffer = reoffer_from(
        &engine,
        "moved",
        "a",
        sdp_for(addr_a, false),
        ProfileFlags::default(),
    )
    .await;
    let presented = sdp::parse(&ok_sdp_text(&reoffer)).expect("parse the re-offer B receives");
    assert_eq!(
        presented.remote_rtp, offered.remote_rtp,
        "B is re-offered the far port it was offered, not A's near port"
    );
    // B answers the re-offer with its SDP unchanged, as the peer in this scenario does.
    answer_from_b(
        &engine,
        "moved",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;

    // B sends where the re-offer told it to, and A — now on its new port — hears it.
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), presented.remote_rtp)
        .await
        .expect("send from B");
    let (data, _) = recv(&phone_a).await;
    assert_eq!(data, rtp(0x0B0B_0B0B), "A hears B after the re-offer");

    // A's own audio from its new port still reaches B.
    phone_a
        .send_to(&rtp(0x0A0A_0A0A), answered.remote_rtp)
        .await
        .expect("send from A");
    let (data, _) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A), "B hears A after the re-offer");

    // And the fix did not come from loosening the gate: B's address sending into A's leg is still
    // dropped, and relays to nobody.
    phone_b
        .send_to(&rtp(0x0BAD_0BAD), answered.remote_rtp)
        .await
        .expect("send from B into the near leg");
    assert_silent(&phone_a, "B's media on A's leg must not reach A").await;
    assert_silent(&phone_b, "B's media on A's leg must not be relayed at all").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_a_presents_the_original_offers_far_endpoints() {
    // Non-muxed, so the RTCP port is presented too. The re-offer must match what B was offered in
    // `c=`, `m=audio` and `a=rtcp`, and differ from what A was answered.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offered = offer_from_a(
        &engine,
        "rtcp",
        sdp_for(addr_a, false),
        ProfileFlags::default(),
    )
    .await;
    let answered = answer_from_b(
        &engine,
        "rtcp",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;

    let reoffer = reoffer_from(
        &engine,
        "rtcp",
        "a",
        sdp_for(addr_a, false),
        ProfileFlags::default(),
    )
    .await;
    let presented = sdp::parse(&ok_sdp_text(&reoffer)).expect("parse re-offer");
    assert_eq!(presented.remote_rtp, offered.remote_rtp);
    assert_eq!(presented.remote_rtcp, offered.remote_rtcp);
    assert_ne!(presented.remote_rtp, answered.remote_rtp);
    assert_ne!(presented.remote_rtcp, answered.remote_rtcp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_a_carries_the_far_interfaces_advertised_address() {
    // Per-leg named interfaces (rtpengine `direction`): near on `internal`, far on `external`, which
    // binds 127.0.0.2 but advertises 127.0.0.3. The re-offer goes to B, so it carries the external
    // advertised address — never the internal one A was answered with.
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
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_interfaces(table);
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let profile = ProfileFlags {
        direction: vec!["internal".into(), "external".into()],
        ..Default::default()
    };
    let offered = offer_from_a(&engine, "dir", sdp_for(addr_a, false), profile.clone()).await;
    assert_eq!(
        offered.remote_rtp.ip(),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))
    );
    answer_from_b(&engine, "dir", sdp_for(addr_b, false), profile.clone()).await;

    let reoffer = reoffer_from(&engine, "dir", "a", sdp_for(addr_a, false), profile).await;
    let text = ok_sdp_text(&reoffer);
    assert!(
        text.contains("c=IN IP4 127.0.0.3"),
        "the re-offer carries the far interface's advertised address: {text}"
    );
    assert_eq!(
        sdp::parse(&text).expect("parse").remote_rtp,
        offered.remote_rtp
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_a_carries_the_far_legs_ice_candidates() {
    // Without a restart: the same credentials, and the far leg's candidates exactly as the offer
    // presented them — not the near leg's, which are what A was answered with.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let offered = offer_from_a(
        &engine,
        "ice-cands",
        ice_offer_with_candidate(addr_a),
        ProfileFlags::default(),
    )
    .await;
    assert!(
        !offered.candidates.is_empty(),
        "the offer re-originated ICE"
    );
    let answered = answer_from_b(
        &engine,
        "ice-cands",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;

    let reoffer = reoffer_from(
        &engine,
        "ice-cands",
        "a",
        reoffer_sdp(addr_a, A_UFRAG, A_PWD),
        ProfileFlags::default(),
    )
    .await;
    let presented = sdp::parse(&ok_sdp_text(&reoffer)).expect("parse re-offer");
    assert_eq!(
        candidate_addresses(&presented),
        candidate_addresses(&offered)
    );
    assert_ne!(
        candidate_addresses(&presented),
        candidate_addresses(&answered)
    );
    assert_eq!(
        presented.ice_ufrag, offered.ice_ufrag,
        "no restart, no churn"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_a_re_presents_an_sdes_far_leg_with_the_same_engine_key() {
    // A secure (SDES, RFC 4568) far leg: B was offered `RTP/SAVP` and the engine's own `a=crypto`.
    // A's plaintext re-offer must reach B the same way — passing A's plain transport through would
    // tell B to drop SRTP mid-call.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        ..Default::default()
    };
    let offered = offer_from_a(&engine, "sdes", sdp_for(addr_a, true), profile.clone()).await;
    let engine_key = *offered.crypto.first().expect("engine a=crypto to B");
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    answer_from_b(
        &engine,
        "sdes",
        savp_answer_sdp(addr_b, &b_key),
        ProfileFlags::default(),
    )
    .await;

    let reoffer = reoffer_from(&engine, "sdes", "a", sdp_for(addr_a, true), profile).await;
    let presented = sdp::parse(&ok_sdp_text(&reoffer)).expect("parse re-offer");
    assert!(presented.secure, "the re-offer keeps B on RTP/SAVP");
    assert!(!presented.dtls);
    assert_eq!(presented.crypto.len(), 1, "one key, the engine's");
    assert_eq!(
        presented.crypto[0].key, engine_key.key,
        "the same engine key B was offered"
    );
    assert_eq!(presented.remote_rtp, offered.remote_rtp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_a_re_presents_a_dtls_far_leg_with_the_same_fingerprint() {
    // A DTLS-SRTP far leg (RFC 5764). A subsequent offer that keeps the association carries the
    // same fingerprint and `a=setup:actpass` (RFC 8842 §5.5 — the offer's role is always actpass;
    // what signals "same association" is the unchanged fingerprint).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let profile = ProfileFlags {
        transport_protocol: Some("UDP/TLS/RTP/SAVPF".into()),
        ..Default::default()
    };
    let offered = offer_from_a(&engine, "dtls", sdp_for(addr_a, true), profile.clone()).await;
    let engine_fingerprint = offered.fingerprint.clone().expect("engine a=fingerprint");
    let peer = siphon_rtp_dtls::DtlsCertificate::generate().expect("peer cert");
    let peer_fingerprint = sdp::Fingerprint {
        hash_function: peer.fingerprint().hash_function,
        bytes: peer.fingerprint().bytes,
    };
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} UDP/TLS/RTP/SAVPF 0\r\na=rtpmap:0 PCMU/8000\r\na=rtcp-mux\r\n\
             a=setup:active\r\na={fingerprint}\r\n",
        ip = addr_b.ip(),
        port = addr_b.port(),
        fingerprint = peer_fingerprint.to_attribute_value(),
    );
    answer_from_b(&engine, "dtls", answer_sdp, ProfileFlags::default()).await;

    let reoffer = reoffer_from(&engine, "dtls", "a", sdp_for(addr_a, true), profile).await;
    let presented = sdp::parse(&ok_sdp_text(&reoffer)).expect("parse re-offer");
    assert!(presented.dtls, "the re-offer keeps B on UDP/TLS/RTP/SAVPF");
    assert_eq!(
        presented.fingerprint,
        Some(engine_fingerprint),
        "the same engine fingerprint B was offered"
    );
    assert_eq!(presented.setup, Some(sdp::Setup::Actpass));
    assert!(presented.crypto.is_empty(), "no SDES keying on a DTLS leg");
    assert_eq!(presented.remote_rtp, offered.remote_rtp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_a_applies_the_rtcp_mux_directive_and_codec_policy_as_the_offer_did() {
    // A muxes, but the `rtcp-mux: demux` directive bound the far leg non-muxed; and `codec-mask`
    // took PCMA out of what B was offered. The re-offer must present B the same.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let profile = ProfileFlags {
        rtcp_mux: vec!["demux".into()],
        flags: vec!["codec-mask-PCMA".into()],
        ..Default::default()
    };
    let offered = offer_from_a(&engine, "policy", sdp_for(addr_a, true), profile.clone()).await;
    assert!(!offered.rtcp_mux, "the far leg was offered demuxed");
    assert_eq!(offered.payload_types, vec![0], "PCMA masked from B");
    answer_from_b(
        &engine,
        "policy",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;

    let reoffer = reoffer_from(&engine, "policy", "a", sdp_for(addr_a, true), profile).await;
    let presented = sdp::parse(&ok_sdp_text(&reoffer)).expect("parse re-offer");
    assert!(!presented.rtcp_mux, "the re-offer keeps B demuxed");
    assert_eq!(presented.remote_rtcp, offered.remote_rtcp);
    assert_eq!(presented.payload_types, offered.payload_types);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_b_presents_the_near_leg_and_the_reversed_answer_the_far_leg() {
    // B (the answerer of the original offer) re-INVITEs from a new port. The engine records it on
    // the far leg and presents A the near leg — exactly what A was answered with. A's answer comes
    // back with the tags reversed and is presented to B on the far leg — exactly what B was offered.
    // Then each party sends where its own SDP told it, and both directions flow.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_phone_b_before, addr_b_before) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let offered = offer_from_a(
        &engine,
        "from-b",
        sdp_for(addr_a, false),
        ProfileFlags::default(),
    )
    .await;
    let answered = answer_from_b(
        &engine,
        "from-b",
        sdp_for(addr_b_before, false),
        ProfileFlags::default(),
    )
    .await;

    let reoffer = reoffer_from(
        &engine,
        "from-b",
        "b",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;
    let to_a = sdp::parse(&ok_sdp_text(&reoffer)).expect("parse the re-offer A receives");
    assert_eq!(to_a.remote_rtp, answered.remote_rtp, "A sees the near leg");
    assert_eq!(to_a.remote_rtcp, answered.remote_rtcp);
    assert_eq!(
        engine
            .calls
            .get("from-b")
            .and_then(|call| call.far_leg().remote_rtp),
        Some(addr_b),
        "B's new address is recorded on the far leg"
    );

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "from-b".into(),
                from_tag: "b".into(),
                to_tag: "a".into(),
                sdp: sdp_for(addr_a, false),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let to_b = sdp::parse(&ok_sdp_text(&answer)).expect("parse the answer B receives");
    assert_eq!(to_b.remote_rtp, offered.remote_rtp, "B sees the far leg");
    assert_eq!(to_b.remote_rtcp, offered.remote_rtcp);
    {
        let call = engine.calls.get("from-b").expect("call");
        assert_eq!(call.from_tag, "a", "the dialog's tags are not swapped");
        assert_eq!(call.to_tag.as_deref(), Some("b"));
    }

    phone_a
        .send_to(&rtp(0x0A0A_0A0A), to_a.remote_rtp)
        .await
        .expect("send from A");
    let (data, _) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A), "B hears A on its new port");
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), to_b.remote_rtp)
        .await
        .expect("send from B");
    let (data, _) = recv(&phone_a).await;
    assert_eq!(data, rtp(0x0B0B_0B0B), "A hears B");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_b_on_a_transcoded_call_keeps_each_party_on_its_own_codec() {
    // The common B-side re-offer is a session refresh that restates B's codec. On a transcoded call
    // A must be shown its own codec, never B's (RFC 3264 §6 — A negotiated PCMU and the engine
    // transcodes), and A's answer must reach B as B's codec. The call stays a transcode.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    // A offers PCMU and PCMA; the mask holds A on PCMU and offers B PCMA alone (the same shape as
    // `codec_mask_still_holds_the_near_leg_on_the_masked_codec`).
    let profile = ProfileFlags {
        flags: vec!["codec-mask-PCMU".into()],
        ..Default::default()
    };
    let offered = offer_from_a(&engine, "transcoded", sdp_for(addr_a, true), profile).await;
    assert_eq!(offered.payload_types, vec![8], "B is offered PCMA only");
    answer_from_b(
        &engine,
        "transcoded",
        sdp_single_codec(addr_b, 8, "PCMA"),
        ProfileFlags::default(),
    )
    .await;
    assert_eq!(
        engine.calls.get("transcoded").map(|call| call.pipeline),
        Some(PipelineKind::Media)
    );

    let reoffer = reoffer_from(
        &engine,
        "transcoded",
        "b",
        sdp_single_codec(addr_b, 8, "PCMA"),
        ProfileFlags::default(),
    )
    .await;
    let to_a = sdp::parse(&ok_sdp_text(&reoffer)).expect("parse re-offer to A");
    assert_eq!(
        to_a.primary_codec().map(|codec| codec.encoding_name),
        Some("PCMU".to_string()),
        "A is shown its own codec"
    );

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "transcoded".into(),
                from_tag: "b".into(),
                to_tag: "a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let to_b = sdp::parse(&ok_sdp_text(&answer)).expect("parse answer to B");
    assert_eq!(
        to_b.primary_codec().map(|codec| codec.encoding_name),
        Some("PCMA".to_string()),
        "B is shown its own codec"
    );
    let call = engine.calls.get("transcoded").expect("call");
    assert_eq!(call.pipeline, PipelineKind::Media, "still a transcode");
    assert_eq!(
        call.near_codec
            .as_ref()
            .map(|codec| codec.encoding_name.as_str()),
        Some("PCMU")
    );
    assert_eq!(
        call.far_codec
            .as_ref()
            .map(|codec| codec.encoding_name.as_str()),
        Some("PCMA")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_b_re_presents_the_near_text_key_to_a_and_the_far_one_to_b() {
    // The secure-text key leak, the other way round: B's re-offer goes to A, so it carries the near
    // text key A was answered with, and A's answer goes to B with the far text key B was offered.
    // Neither party is ever handed the key that protects the engine's text toward the other.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a_audio, addr_a_audio) = phone().await;
    let (_phone_a_text, addr_a_text) = phone().await;
    let (_phone_b_audio, addr_b_audio) = phone().await;
    let (_phone_b_text, addr_b_text) = phone().await;
    let a_text_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen a");
    let b_text_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen b");
    let offered = offer_from_a(
        &engine,
        "sec-rtt-from-b",
        audio_secure_text_sdp(addr_a_audio, addr_a_text, &a_text_key),
        ProfileFlags::default(),
    )
    .await;
    let far_text = offered.text.expect("offer anchored secure text");
    let answered = answer_from_b(
        &engine,
        "sec-rtt-from-b",
        audio_secure_text_sdp(addr_b_audio, addr_b_text, &b_text_key),
        ProfileFlags::default(),
    )
    .await;
    let near_text = answered.text.expect("answer anchored secure text");

    let reoffer = reoffer_from(
        &engine,
        "sec-rtt-from-b",
        "b",
        audio_secure_text_sdp(addr_b_audio, addr_b_text, &b_text_key),
        ProfileFlags::default(),
    )
    .await;
    let to_a = sdp::parse(&ok_sdp_text(&reoffer))
        .expect("parse re-offer to A")
        .text
        .expect("text re-anchored");
    assert!(to_a.secure);
    assert_eq!(to_a.remote_rtp, near_text.remote_rtp, "A's own text port");
    assert_eq!(to_a.crypto[0].key, near_text.crypto[0].key, "A's own key");
    assert_ne!(to_a.crypto[0].key, far_text.crypto[0].key, "never B's");

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "sec-rtt-from-b".into(),
                from_tag: "b".into(),
                to_tag: "a".into(),
                sdp: audio_secure_text_sdp(addr_a_audio, addr_a_text, &a_text_key),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let to_b = sdp::parse(&ok_sdp_text(&answer))
        .expect("parse answer to B")
        .text
        .expect("text anchored");
    assert!(to_b.secure);
    assert_eq!(to_b.remote_rtp, far_text.remote_rtp, "B's own text port");
    assert_eq!(to_b.crypto[0].key, far_text.crypto[0].key, "B's own key");
    assert_ne!(to_b.crypto[0].key, near_text.crypto[0].key, "never A's");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_b_keeps_an_sdes_far_leg_secure_or_is_refused() {
    // B's re-offer on an SDES far leg: A is shown its plaintext near leg, and A's answer reaches B
    // as `RTP/SAVP` with the engine's own far key under the tag B offered (RFC 4568 §5.1.2). A
    // re-offer from B that drops SRTP is refused — never bridged in the clear.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        ..Default::default()
    };
    let offered = offer_from_a(&engine, "sdes-from-b", sdp_for(addr_a, true), profile).await;
    let engine_key = offered.crypto[0];
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let answered = answer_from_b(
        &engine,
        "sdes-from-b",
        savp_answer_sdp(addr_b, &b_key),
        ProfileFlags::default(),
    )
    .await;

    let downgrade = reoffer_from(
        &engine,
        "sdes-from-b",
        "b",
        sdp_for(addr_b, true),
        ProfileFlags::default(),
    )
    .await;
    match downgrade {
        CmdResult::Error { reason } => assert!(reason.contains("SDES"), "{reason}"),
        other => panic!("a re-offer dropping SRTP must be refused, got {other:?}"),
    }

    // B re-keys under another tag: allowed (RFC 4568 §5.1.4), answered under B's tag.
    let b_new_key = CryptoAttribute::generate(2, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let reoffer = reoffer_from(
        &engine,
        "sdes-from-b",
        "b",
        savp_answer_sdp(addr_b, &b_new_key),
        ProfileFlags::default(),
    )
    .await;
    let to_a = sdp::parse(&ok_sdp_text(&reoffer)).expect("parse re-offer to A");
    assert!(!to_a.secure, "A's side of an SDES bridge is plaintext");
    assert!(to_a.crypto.is_empty(), "and never carries B's key");
    assert_eq!(to_a.remote_rtp, answered.remote_rtp);

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "sdes-from-b".into(),
                from_tag: "b".into(),
                to_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let to_b = sdp::parse(&ok_sdp_text(&answer)).expect("parse answer to B");
    assert!(to_b.secure, "B stays on RTP/SAVP");
    assert_eq!(to_b.crypto.len(), 1);
    assert_eq!(to_b.crypto[0].key, engine_key.key, "the engine's far key");
    assert_eq!(to_b.crypto[0].tag, 2, "under the tag B's re-offer used");
    assert_eq!(to_b.remote_rtp, offered.remote_rtp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dtls_leg_keeps_its_association_across_a_renegotiation() {
    use crate::srtp_bridge::run_redirect_dispatcher;

    // RFC 8842 §5.5: a subsequent offer carrying the same fingerprint tells the peer to keep the
    // DTLS association it already has, so it does not handshake again. The engine's answer re-run
    // rebuilt the bridge from nothing — dropping the keyed leg and waiting for a handshake that
    // never comes — so any renegotiation of a DTLS call (a session refresh, hold, an ICE restart)
    // silently ended its media while every counter still read healthy. Only a changed fingerprint
    // or role is a new association (RFC 8842 §3.1), and that case is the second half of this test.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
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
        "dtls-reneg",
        sdp_for(addr_a, true),
        profile.clone(),
    )
    .await;
    let engine_fingerprint = offered.fingerprint.clone().expect("engine a=fingerprint");
    let engine_far = offered.remote_rtp;
    let peer_cert = siphon_rtp_dtls::DtlsCertificate::generate().expect("peer cert");
    answer_from_b(
        &engine,
        "dtls-reneg",
        dtls_answer_sdp(addr_b, 0, "PCMU", &peer_cert, sdp::Setup::Active),
        ProfileFlags::default(),
    )
    .await;
    let mut peer_leg = peer_dtls_handshake(
        peer_b.clone(),
        addr_b,
        engine_far,
        &peer_cert,
        &engine_fingerprint,
    )
    .await;

    // One protected packet from B, relayed to A as plaintext. Every attempt carries a fresh
    // sequence number: SRTP replay protection (RFC 3711 §3.3.2) rejects a repeat, and a real peer
    // never sends one. Retried to absorb the window between B finishing its handshake and the
    // engine installing the leg.
    let mut sequence = 100u16;
    let mut protect_next = |peer_leg: &mut siphon_rtp_srtp::leg::SecureLeg| {
        sequence = sequence.wrapping_add(1);
        let media = rtp_packet(sequence, 0x0B0B_0B0B);
        let mut sealed = Vec::new();
        peer_leg
            .protect(&media, &mut sealed)
            .expect("peer protects");
        (media, sealed)
    };
    let mut relayed = None;
    for _ in 0..25 {
        let (media, sealed) = protect_next(&mut peer_leg);
        peer_b.send_to(&sealed, engine_far).await.expect("b sends");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            relayed = Some((buffer[..len].to_vec(), media));
            break;
        }
    }
    let (relayed, expected) = relayed.expect("A receives B's media once the handshake completes");
    assert_eq!(relayed, expected);

    // The renegotiation: A re-offers, B answers with the same fingerprint and role — and, like a
    // real peer, does not handshake again.
    reoffer_from(
        &engine,
        "dtls-reneg",
        "a",
        sdp_for(addr_a, true),
        profile.clone(),
    )
    .await;
    answer_from_b(
        &engine,
        "dtls-reneg",
        dtls_answer_sdp(addr_b, 0, "PCMU", &peer_cert, sdp::Setup::Active),
        ProfileFlags::default(),
    )
    .await;

    let mut relayed = None;
    for _ in 0..25 {
        let (media, sealed) = protect_next(&mut peer_leg);
        peer_b.send_to(&sealed, engine_far).await.expect("b sends");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            relayed = Some((buffer[..len].to_vec(), media));
            break;
        }
    }
    let (relayed, expected) =
        relayed.expect("the association survived the renegotiation, with no second handshake");
    assert_eq!(relayed, expected);

    // A different peer certificate *is* a new association (RFC 8842 §3.1): the old leg's media
    // stops being relayed, because the engine is now waiting for the handshake that goes with it.
    let other_cert = siphon_rtp_dtls::DtlsCertificate::generate().expect("second peer cert");
    reoffer_from(&engine, "dtls-reneg", "a", sdp_for(addr_a, true), profile).await;
    answer_from_b(
        &engine,
        "dtls-reneg",
        dtls_answer_sdp(addr_b, 0, "PCMU", &other_cert, sdp::Setup::Active),
        ProfileFlags::default(),
    )
    .await;
    let (_, sealed) = protect_next(&mut peer_leg);
    peer_b.send_to(&sealed, engine_far).await.expect("b sends");
    assert_silent(
        &phone_a,
        "a changed fingerprint starts a new association, so the old leg's media is dropped",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transcoding_dtls_leg_is_re_keyed_when_its_answer_rebuilds_its_actor() {
    use crate::srtp_bridge::run_redirect_dispatcher;

    // The other half of keeping a DTLS association: on a leg whose media goes through the
    // transcode pipeline, the answer rebuilds the media actor, and a rebuilt actor starts
    // *pending* — it drops media until a key arrives. The handshake that produced that key already
    // happened and will not happen again, so the kept association has to hand the rebuilt actor
    // the same leg. Without that the call is silent from the renegotiation onward.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
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
    // A on PCMU, B on PCMA: a codec mismatch on a DTLS far leg is what takes the media pipeline.
    let offered = offer_from_a(
        &engine,
        "dtls-xcode-reneg",
        sdp_single_codec(addr_a, 0, "PCMU"),
        profile.clone(),
    )
    .await;
    let engine_fingerprint = offered.fingerprint.clone().expect("engine a=fingerprint");
    let engine_far = offered.remote_rtp;
    let peer_cert = siphon_rtp_dtls::DtlsCertificate::generate().expect("peer cert");
    answer_from_b(
        &engine,
        "dtls-xcode-reneg",
        dtls_answer_sdp(addr_b, 8, "PCMA", &peer_cert, sdp::Setup::Active),
        ProfileFlags::default(),
    )
    .await;
    assert_eq!(
        engine
            .calls
            .get("dtls-xcode-reneg")
            .map(|call| call.pipeline),
        Some(PipelineKind::DtlsMedia)
    );
    let mut peer_leg = peer_dtls_handshake(
        peer_b.clone(),
        addr_b,
        engine_far,
        &peer_cert,
        &engine_fingerprint,
    )
    .await;

    // A full 20 ms A-law frame per attempt, so the transcoder has something to re-encode, each
    // with a fresh sequence number (SRTP replay, RFC 3711 §3.3.2).
    let mut sequence = 200u16;
    let mut protect_next = |peer_leg: &mut siphon_rtp_srtp::leg::SecureLeg| {
        sequence = sequence.wrapping_add(1);
        let mut media = vec![0x80, 8];
        media.extend_from_slice(&sequence.to_be_bytes());
        media.extend_from_slice(&u32::from(sequence).to_be_bytes());
        media.extend_from_slice(&0x0B0B_0B0Bu32.to_be_bytes());
        media.extend_from_slice(&[0xD5; 160]);
        let mut sealed = Vec::new();
        peer_leg
            .protect(&media, &mut sealed)
            .expect("peer protects");
        sealed
    };
    // The transcoded egress reaches A as PCMU (payload type 0), which is only possible once the
    // actor holds the key.
    let mut transcoded = None;
    for _ in 0..25 {
        let sealed = protect_next(&mut peer_leg);
        peer_b.send_to(&sealed, engine_far).await.expect("b sends");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            transcoded = Some(buffer[..len].to_vec());
            break;
        }
    }
    let relayed = transcoded.expect("A receives the transcoded stream once the handshake keys it");
    assert_eq!(relayed[1] & 0x7f, 0, "re-encoded to A's PCMU");

    // The renegotiation rebuilds the actor; the association (and its key) must carry over.
    reoffer_from(
        &engine,
        "dtls-xcode-reneg",
        "a",
        sdp_single_codec(addr_a, 0, "PCMU"),
        profile,
    )
    .await;
    answer_from_b(
        &engine,
        "dtls-xcode-reneg",
        dtls_answer_sdp(addr_b, 8, "PCMA", &peer_cert, sdp::Setup::Active),
        ProfileFlags::default(),
    )
    .await;

    let mut transcoded = None;
    for _ in 0..25 {
        let sealed = protect_next(&mut peer_leg);
        peer_b.send_to(&sealed, engine_far).await.expect("b sends");
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(150), phone_a.recv_from(&mut buffer)).await
        {
            transcoded = Some(buffer[..len].to_vec());
            break;
        }
    }
    let relayed =
        transcoded.expect("the rebuilt actor was re-keyed with the association's own leg");
    assert_eq!(relayed[1] & 0x7f, 0, "still re-encoded to A's PCMU");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_sdes_bridge_keeps_its_srtp_rollover_across_a_renegotiation() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_srtp::SrtpContext;

    // RFC 3711 §3.3.1: the rollover counter belongs to the *stream*, not to the key — each side
    // estimates it from the sequence numbers it has seen. An answer re-run on a live call (what
    // every renegotiation does here) rebuilt the leg's SRTP contexts from the keys alone, which
    // restarts both counters at 0 while the peer's keep counting, so every packet after that
    // authenticates against the wrong index and the call goes silent in both directions. It only
    // bites once a call has run past a sequence wrap — about 21 minutes at a 20 ms ptime, which is
    // squarely inside session-timer territory.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let profile = ProfileFlags {
        transport_protocol: Some("RTP/SAVP".into()),
        ..Default::default()
    };
    let offered = offer_from_a(&engine, "srtp-roc", sdp_for(addr_a, true), profile.clone()).await;
    let engine_far_key = offered.crypto[0];
    let b_key = CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("gen");
    let answered = answer_from_b(
        &engine,
        "srtp-roc",
        savp_answer_sdp(addr_b, &b_key),
        ProfileFlags::default(),
    )
    .await;
    let engine_near = answered.remote_rtp;
    let engine_far = offered.remote_rtp;

    // B's own contexts: it decrypts the engine's stream with the engine's key and encrypts with
    // its own — the mapping `SecureLeg::new` pins.
    let mut b_inbound = SrtpContext::from_key_material(&engine_far_key.key);
    let mut b_outbound = SrtpContext::from_key_material(&b_key.key);
    // Run both directions across a sequence-number wrap, so every counter involved is at 1.
    for sequence in [65_534u16, 65_535, 0, 1] {
        let from_a = rtp_packet(sequence, 0x0A0A_0A0A);
        phone_a
            .send_to(&from_a, engine_near)
            .await
            .expect("A sends");
        let (sealed, _) = recv(&phone_b).await;
        let mut plain = Vec::new();
        b_inbound
            .unprotect(&sealed, &mut plain)
            .expect("B decrypts the engine's stream");
        assert_eq!(plain, from_a);

        let from_b = rtp_packet(sequence, 0x0B0B_0B0B);
        let mut sealed_b = Vec::new();
        b_outbound
            .protect(&from_b, &mut sealed_b)
            .expect("B protects");
        phone_b
            .send_to(&sealed_b, engine_far)
            .await
            .expect("B sends");
        let (relayed, _) = recv(&phone_a).await;
        assert_eq!(relayed, from_b);
    }

    // The renegotiation: A re-offers, B answers with the key it already had.
    reoffer_from(&engine, "srtp-roc", "a", sdp_for(addr_a, true), profile).await;
    answer_from_b(
        &engine,
        "srtp-roc",
        savp_answer_sdp(addr_b, &b_key),
        ProfileFlags::default(),
    )
    .await;

    // Both directions still authenticate, so the leg continued its rollover rather than restarting.
    let from_a = rtp_packet(2, 0x0A0A_0A0A);
    phone_a
        .send_to(&from_a, engine_near)
        .await
        .expect("A sends");
    let (sealed, _) = recv(&phone_b).await;
    let mut plain = Vec::new();
    b_inbound
        .unprotect(&sealed, &mut plain)
        .expect("B still decrypts the engine's stream after the renegotiation");
    assert_eq!(plain, from_a);

    let from_b = rtp_packet(2, 0x0B0B_0B0B);
    let mut sealed_b = Vec::new();
    b_outbound
        .protect(&from_b, &mut sealed_b)
        .expect("B protects");
    phone_b
        .send_to(&sealed_b, engine_far)
        .await
        .expect("B sends");
    let (relayed, _) = recv(&phone_a).await;
    assert_eq!(
        relayed, from_b,
        "the engine still decrypts B's stream after the renegotiation"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_on_a_locally_answered_call_presents_the_callers_only_leg() {
    // `answer_local` owns one leg, and its caller reaches it: a re-offer from the caller can only
    // present that leg.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ivr".into(),
                from_tag: "a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answered = sdp::parse(&ok_sdp_text(&answered)).expect("parse local answer");
    let reoffer = reoffer_from(
        &engine,
        "ivr",
        "a",
        sdp_single_codec(addr_a, 0, "PCMU"),
        ProfileFlags::default(),
    )
    .await;
    assert_eq!(
        sdp::parse(&ok_sdp_text(&reoffer))
            .expect("parse re-offer")
            .remote_rtp,
        answered.remote_rtp
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_is_refused_for_an_unknown_tag_another_client_or_b_before_an_answer() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    offer_from_a(
        &engine,
        "tags",
        sdp_for(addr_a, false),
        ProfileFlags::default(),
    )
    .await;

    // No answered B yet, so there is no B to re-offer from.
    let early = reoffer_from(
        &engine,
        "tags",
        "b",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;
    assert!(matches!(early, CmdResult::Error { .. }), "{early:?}");

    answer_from_b(
        &engine,
        "tags",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;
    let stranger = reoffer_from(
        &engine,
        "tags",
        "c",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;
    match stranger {
        CmdResult::Error { reason } => assert!(reason.contains("unknown"), "{reason}"),
        other => panic!("an unknown tag must be refused, got {other:?}"),
    }
    let intruder = engine
        .handle(
            ClientId(99),
            Command::Reoffer {
                call_id: "tags".into(),
                from_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(intruder, CmdResult::Error { .. }), "{intruder:?}");

    // B cannot silently switch codec either: the guard applies to whichever party re-offers.
    let switched = reoffer_from(
        &engine,
        "tags",
        "b",
        sdp_single_codec(addr_b, 8, "PCMA"),
        ProfileFlags::default(),
    )
    .await;
    match switched {
        CmdResult::Error { reason } => assert!(reason.contains("codec"), "{reason}"),
        other => panic!("a codec change from B must be refused, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reversed_answer_with_no_reoffer_from_b_outstanding_is_refused_and_changes_nothing() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let (_phone_x, addr_x) = phone().await;
    offer_from_a(
        &engine,
        "stray",
        sdp_for(addr_a, false),
        ProfileFlags::default(),
    )
    .await;
    answer_from_b(
        &engine,
        "stray",
        sdp_for(addr_b, false),
        ProfileFlags::default(),
    )
    .await;

    let stray = || Command::Answer {
        call_id: "stray".into(),
        from_tag: "b".into(),
        to_tag: "a".into(),
        sdp: sdp_for(addr_x, false),
        profile: ProfileFlags::default(),
    };
    let refused = engine.handle(CLIENT, stray()).await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");

    // A re-offer from A is outstanding, not one from B: still refused.
    reoffer_from(
        &engine,
        "stray",
        "a",
        sdp_for(addr_a, false),
        ProfileFlags::default(),
    )
    .await;
    let refused = engine.handle(CLIENT, stray()).await;
    assert!(matches!(refused, CmdResult::Error { .. }), "{refused:?}");

    let call = engine.calls.get("stray").expect("call");
    assert_eq!(call.near.remote_rtp, Some(addr_a), "A's leg untouched");
    assert_eq!(call.far_leg().remote_rtp, Some(addr_b), "B's leg untouched");
    assert_eq!(call.from_tag, "a");
    assert_eq!(call.to_tag.as_deref(), Some("b"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_a_new_public_address_moves_the_near_gate_with_it() {
    // A NATed app switches network: new public address, new private `c=`. The re-offer's
    // `received-from` is the proxy-observed new source and must replace the stored hint, or the
    // answer rebuilds the near gate as (old public IP, new port) and every packet from the new
    // address is dropped.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a_before, addr_a_before) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 4)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    offer_from_a(
        &engine,
        "roam-a",
        sdp_with_conn(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            addr_a_before.port(),
            0,
            "PCMU",
        ),
        ProfileFlags {
            received_from: Some(addr_a_before.ip()),
            ..Default::default()
        },
    )
    .await;
    let answered = answer_from_b(
        &engine,
        "roam-a",
        sdp_single_codec(addr_b, 0, "PCMU"),
        ProfileFlags::default(),
    )
    .await;

    reoffer_from(
        &engine,
        "roam-a",
        "a",
        sdp_with_conn(
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2)),
            addr_a.port(),
            0,
            "PCMU",
        ),
        ProfileFlags {
            received_from: Some(addr_a.ip()),
            ..Default::default()
        },
    )
    .await;
    answer_from_b(
        &engine,
        "roam-a",
        sdp_single_codec(addr_b, 0, "PCMU"),
        ProfileFlags::default(),
    )
    .await;

    phone_a_before
        .send_to(&rtp(0x0101_0101), answered.remote_rtp)
        .await
        .expect("send from the old address");
    assert_silent(&phone_b, "the old public address no longer passes the gate").await;
    phone_a
        .send_to(&rtp(0x0A0A_0A0A), answered.remote_rtp)
        .await
        .expect("send from the new address");
    let (data, _) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A), "the new public address is relayed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reoffer_from_b_on_a_new_public_address_moves_the_far_gate_with_it() {
    // The same, for B: its answer's hint is stored, and its re-offer's hint replaces it.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_b_before, addr_b_before) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 5)).await;
    let offered = offer_from_a(
        &engine,
        "roam-b",
        sdp_single_codec(addr_a, 0, "PCMU"),
        ProfileFlags::default(),
    )
    .await;
    answer_from_b(
        &engine,
        "roam-b",
        sdp_with_conn(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            addr_b_before.port(),
            0,
            "PCMU",
        ),
        ProfileFlags {
            received_from: Some(addr_b_before.ip()),
            ..Default::default()
        },
    )
    .await;

    let reoffer = reoffer_from(
        &engine,
        "roam-b",
        "b",
        sdp_with_conn(
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 3)),
            addr_b.port(),
            0,
            "PCMU",
        ),
        ProfileFlags {
            received_from: Some(addr_b.ip()),
            ..Default::default()
        },
    )
    .await;
    assert!(matches!(reoffer, CmdResult::Ok { .. }), "{reoffer:?}");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "roam-b".into(),
                from_tag: "b".into(),
                to_tag: "a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    assert!(matches!(answer, CmdResult::Ok { .. }), "{answer:?}");

    phone_b_before
        .send_to(&rtp(0x0101_0101), offered.remote_rtp)
        .await
        .expect("send from the old address");
    assert_silent(&phone_a, "B's old public address no longer passes the gate").await;
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), offered.remote_rtp)
        .await
        .expect("send from the new address");
    let (data, _) = recv(&phone_a).await;
    assert_eq!(data, rtp(0x0B0B_0B0B), "B's new public address is relayed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renegotiation_without_received_from_keeps_each_stored_hint() {
    // Both parties NATed behind private `c=` addresses, each hint supplied once. A re-offer without
    // a hint, and B's answer to it without one, must keep gating each party to its public address
    // rather than falling back to the private one it signalled.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;
    let a_sdp = || {
        sdp_with_conn(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            addr_a.port(),
            0,
            "PCMU",
        )
    };
    let b_sdp = || {
        sdp_with_conn(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            addr_b.port(),
            0,
            "PCMU",
        )
    };
    let offered = offer_from_a(
        &engine,
        "keep-hints",
        a_sdp(),
        ProfileFlags {
            received_from: Some(addr_a.ip()),
            ..Default::default()
        },
    )
    .await;
    let answered = answer_from_b(
        &engine,
        "keep-hints",
        b_sdp(),
        ProfileFlags {
            received_from: Some(addr_b.ip()),
            ..Default::default()
        },
    )
    .await;

    reoffer_from(&engine, "keep-hints", "a", a_sdp(), ProfileFlags::default()).await;
    answer_from_b(&engine, "keep-hints", b_sdp(), ProfileFlags::default()).await;

    phone_a
        .send_to(&rtp(0x0A0A_0A0A), answered.remote_rtp)
        .await
        .expect("send from A");
    let (data, _) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x0A0A_0A0A), "A still passes its gate");
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), offered.remote_rtp)
        .await
        .expect("send from B");
    let (data, _) = recv(&phone_a).await;
    assert_eq!(data, rtp(0x0B0B_0B0B), "B still passes its gate");
}

// ---- duplicate offer on a live call-id -------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_offer_replaces_the_call_without_leaking_ports_or_quota() {
    // A repeated offer used to overwrite the registry entry and drop the old `Call` on the floor:
    // its endpoints were never freed and its quota slot never released, so a client repeating an
    // offer (what a SIP re-INVITE looks like from here) bled ports and quota until the node
    // refused calls.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let client = ClientId(21);
    let events = engine.register_client(client);
    let (_phone, addr) = phone().await;

    let first = engine
        .handle(
            client,
            Command::Offer {
                call_id: "dup".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr, false),
                profile: Default::default(),
            },
        )
        .await;
    let first_port = sdp::parse(&ok_sdp_text(&first))
        .expect("parse")
        .remote_rtp
        .port();
    let first_endpoints: Vec<EndpointId> = engine
        .calls
        .get("dup")
        .map(|call| call.endpoint_ids().collect())
        .expect("call exists");

    let second = engine
        .handle(
            client,
            Command::Offer {
                call_id: "dup".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr, false),
                profile: Default::default(),
            },
        )
        .await;
    let second_port = sdp::parse(&ok_sdp_text(&second))
        .expect("parse")
        .remote_rtp
        .port();

    assert_eq!(engine.session_count(), 1, "one call, not two");
    assert_eq!(
        engine.client_calls.get(&client).map(|count| *count),
        Some(1),
        "the quota slot of the replaced call is released, not leaked"
    );
    // The old endpoints are gone from the datapath, not merely forgotten by the engine.
    for endpoint in first_endpoints {
        assert_eq!(
            engine.datapath().stats(endpoint),
            None,
            "the replaced call's endpoint {endpoint:?} was freed"
        );
    }
    assert_ne!(first_port, second_port, "the replacement bound fresh ports");

    // The replaced call is reported as ended, with its own reason — and not as a dead path.
    let mut summary_reason = None;
    while let Ok(event) = events.try_recv() {
        match event {
            Event::CallSummary { reason, .. } => summary_reason = Some(reason),
            Event::MediaTimeout { .. } => {
                panic!("a controller-driven replacement is not a media timeout")
            }
            _ => {}
        }
    }
    assert_eq!(summary_reason.as_deref(), Some("replaced"));

    // And the surviving call still works end to end.
    let (_phone_b, addr_b) = phone().await;
    let answer = engine
        .handle(
            client,
            Command::Answer {
                call_id: "dup".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(answer, CmdResult::Ok { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_client_cannot_replace_a_call_it_does_not_own() {
    // A3 (docs/security-and-nat.md §5): only the owning client may affect a call. Before this,
    // any client could offer an existing call-id and destroy someone else's call.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let owner = ClientId(31);
    let intruder = ClientId(32);
    let (_phone, addr) = phone().await;

    let first = engine
        .handle(
            owner,
            Command::Offer {
                call_id: "owned".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr, false),
                profile: Default::default(),
            },
        )
        .await;
    let owner_port = sdp::parse(&ok_sdp_text(&first))
        .expect("parse")
        .remote_rtp
        .port();

    let stolen = engine
        .handle(
            intruder,
            Command::Offer {
                call_id: "owned".into(),
                from_tag: "x".into(),
                sdp: sdp_for(addr, false),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(stolen, CmdResult::Error { .. }),
        "an unrelated client is refused: {stolen:?}"
    );

    // The owner's call is untouched: same ports, same owner, still answerable.
    assert_eq!(engine.session_count(), 1);
    let call = engine.calls.get("owned").expect("still there");
    assert_eq!(call.owner, owner);
    assert_eq!(call.far_leg().rtp.local_addr.port(), owner_port);
    drop(call);
    // And the intruder was charged nothing.
    assert_eq!(engine.client_calls.get(&intruder).map(|count| *count), None);
}

// ---- RFC 8839 §5.3 ice-mismatch --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rewritten_offer_is_answered_with_ice_mismatch_and_no_ice() {
    // A SIP ALG rewrote `c=`/`m=` to its own address but left the candidates alone, so the
    // candidates describe a topology that no longer matches where media goes. RFC 8839 §5.3: say
    // `a=ice-mismatch` and fall back to the signalled address rather than running ICE on a lie.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let mangled = format!(
        "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             a=ice-ufrag:{A_UFRAG}\r\na=ice-pwd:{A_PWD}\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=candidate:peer 1 UDP 2130706431 198.51.100.77 5555 typ host\r\n",
        ip = addr_a.ip(),
        port = addr_a.port()
    );
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "alg".into(),
                from_tag: "a".into(),
                sdp: mangled,
                profile: Default::default(),
            },
        )
        .await;
    let far = ok_sdp_text(&offer);

    assert!(far.contains("a=ice-mismatch"), "{far}");
    assert!(
        !far.contains("a=ice-lite"),
        "no ICE is re-originated: {far}"
    );
    assert!(!far.contains("a=ice-ufrag"), "and no credentials: {far}");
    // The peer's stale candidate is not forwarded either.
    assert!(!far.contains("198.51.100.77"), "{far}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_consistent_ice_offer_is_not_treated_as_a_mismatch() {
    // The candidate matches the default destination, so the SDP reached us intact — ICE runs.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "intact".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let far = ok_sdp_text(&offer);
    assert!(!far.contains("a=ice-mismatch"), "{far}");
    assert!(far.contains("a=ice-lite"), "ICE is re-originated: {far}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ice_force_overrides_the_mismatch_heuristic() {
    // An operator who forces ICE has said they know better than the §5.3 heuristic.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let mangled = format!(
        "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             a=ice-ufrag:{A_UFRAG}\r\na=ice-pwd:{A_PWD}\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=candidate:peer 1 UDP 2130706431 198.51.100.77 5555 typ host\r\n",
        ip = addr_a.ip(),
        port = addr_a.port()
    );
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "forced".into(),
                from_tag: "a".into(),
                sdp: mangled,
                profile: ProfileFlags {
                    ice: Some("force".into()),
                    ..Default::default()
                },
            },
        )
        .await;
    let far = ok_sdp_text(&offer);
    assert!(!far.contains("a=ice-mismatch"), "{far}");
    assert!(
        far.contains("a=ice-lite"),
        "forced ICE still re-originates: {far}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_answering_ice_mismatch_disables_ice_on_that_leg() {
    // B tells us our offer's ICE arrived altered (RFC 8839 §5.3). The far leg must then run
    // without ICE — leaving the responder armed would gate media on checks B will never send.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "mismatch-answer".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let answer_sdp = format!(
        "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             a=ice-ufrag:BBBBBB\r\na=ice-pwd:bpasswordbpasswordbpas\r\na=ice-mismatch\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr_b.ip(),
        port = addr_b.port()
    );
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "mismatch-answer".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: answer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    let far_rtp = engine
        .calls
        .get("mismatch-answer")
        .map(|call| call.far_leg().rtp.id)
        .expect("call");
    assert_eq!(
        engine.datapath().ice_validated_source(far_rtp),
        None,
        "the far leg carries no ICE credentials at all"
    );

    // And B's media relays to A on the plain signalled-source path.
    let far_addr = engine
        .calls
        .get("mismatch-answer")
        .map(|call| call.far_leg().rtp.local_addr)
        .expect("call");
    phone_b
        .send_to(&rtp(0x0B0B_0B0B), far_addr)
        .await
        .expect("send from B");
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(1), phone_a.recv_from(&mut buffer))
        .await
        .expect("B's media reaches A without ICE")
        .expect("recv");
    assert_eq!(&buffer[..len], rtp(0x0B0B_0B0B).as_slice());
}

// ---- RFC 8445 full agent (end-to-end over the real datapath) ---------------------------------

/// Build the peer-side ICE agent for a phone at `local`, from the engine's own advertised SDP.
/// The peer is **controlling**: it offered ICE, and RFC 8445 §6.1.1 gives the offerer that role.
fn peer_agent(engine_sdp: &sdp::MediaInfo, local: SocketAddr) -> siphon_rtp_ice::IceAgent {
    use siphon_rtp_ice::agent::{AgentConfig, Credentials};
    let local_candidate = siphon_rtp_ice::Candidate::new(
        "peer".to_string(),
        1,
        local,
        siphon_rtp_ice::CandidateKind::Host,
        65535,
    );
    siphon_rtp_ice::IceAgent::new(
        AgentConfig::new(
            Credentials::new(A_UFRAG, A_PWD),
            Credentials::new(
                engine_sdp.ice_ufrag.clone().expect("engine ufrag"),
                engine_sdp.ice_pwd.clone().expect("engine pwd"),
            ),
            true,
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

/// An ICE offer from A that also carries its host candidate, so the engine's agent has something
/// to pair against.
fn ice_offer_with_candidate(addr: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             a=ice-ufrag:{A_UFRAG}\r\na=ice-pwd:{A_PWD}\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n\
             a=candidate:peer 1 UDP 2130706431 {ip} {port} typ host\r\n\
             a=end-of-candidates\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_ice_leg_opens_its_media_path_only_after_a_pair_is_selected() {
    // The end-to-end proof that the agent is wired: a real peer agent runs against the engine's
    // over the loopback datapath, and media is gated on ICE's decision rather than on arrival.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "full".into(),
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
                call_id: "full".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("parse answer");
    let engine_near = near.remote_rtp;
    let near_rtp = engine
        .calls
        .get("full")
        .map(|call| call.near.rtp.id)
        .expect("call");

    // Before ICE runs, nothing has been adopted — so A's media would be dropped.
    assert_eq!(engine.datapath().ice_validated_source(near_rtp), None);

    // Drive both agents until the engine selects a pair.
    let mut peer = peer_agent(&near, addr_a);
    let mut buffer = [0u8; 2048];
    let mut now = 0u64;
    while now < 4_000 && engine.datapath().ice_validated_source(near_rtp).is_none() {
        for action in peer.poll(now) {
            if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                phone_a.send_to(&datagram, to).await.expect("peer send");
            }
        }
        engine.drive_ice_agents(now).await;
        // Drain whatever the engine sent back into the peer agent.
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(20), phone_a.recv_from(&mut buffer)).await
        {
            for action in peer.on_datagram(addr_a, from, &buffer[..len], now) {
                if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                    phone_a.send_to(&datagram, to).await.expect("peer send");
                }
            }
            engine.drive_ice_agents(now).await;
        }
        now += 20;
    }

    // ICE selected A's real transport address, and the datapath adopted it.
    assert_eq!(
        engine.datapath().ice_validated_source(near_rtp),
        Some(addr_a),
        "the agent adopted the selected pair's remote"
    );
    assert_eq!(engine_near.ip(), addr_a.ip(), "same loopback family");

    // And now media flows A -> engine -> B.
    phone_a
        .send_to(&rtp(0x0A0A_0A0A), engine_near)
        .await
        .expect("send media");
    let (len, _) = timeout(Duration::from_secs(1), phone_b.recv_from(&mut buffer))
        .await
        .expect("media reaches B once ICE has chosen a pair")
        .expect("recv");
    assert_eq!(&buffer[..len], rtp(0x0A0A_0A0A).as_slice());
}

// ---- Full ICE on a conference seat (RFC 8445 + the room actor) ------------------------------

// ---- Relayed candidates (RFC 5766 TURN client end-to-end) -----------------------------------

const TURN_USER: &str = "turnuser";

const TURN_PASSWORD: &str = "turnpassword";

const TURN_REALM: &str = "siphon.invalid";

/// A minimal RFC 5766 TURN server: challenges the first Allocate with `401` + REALM/NONCE, then
/// grants the allocation and answers CreatePermission / ChannelBind. Enough to drive the client
/// through its real state machine — the challenge, the signed retry, the relayed address — over a
/// real socket, rather than asserting against fixtures the client itself produced.
///
/// Returns its address and the relayed address it will hand out.
async fn fake_turn_server() -> (SocketAddr, SocketAddr) {
    use siphon_rtp_stun::turn;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind turn");
    let server_addr = socket.local_addr().expect("turn addr");
    // The relayed transport the server "assigns" — a distinct port on the same host.
    let relayed: SocketAddr = "127.0.0.1:59999".parse().expect("relayed addr");
    tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            let Ok(request) = siphon_rtp_stun::parse(&buffer[..len]) else {
                continue;
            };
            let method = turn::method_of(request.message_type);
            let id = request.transaction_id;
            let signed = request.attribute(turn::ATTR_MESSAGE_INTEGRITY).is_some();
            let response = match (method, signed) {
                // RFC 5766 §6.2: an unauthenticated Allocate MUST be challenged.
                (turn::METHOD_ALLOCATE, false) => siphon_rtp_stun::MessageBuilder::new(
                    turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_ERROR),
                    &id,
                )
                .attribute(
                    turn::ATTR_ERROR_CODE,
                    &turn::error_code_value(turn::ERROR_UNAUTHORIZED, "Unauthorized"),
                )
                .attribute(turn::ATTR_REALM, TURN_REALM.as_bytes())
                .attribute(turn::ATTR_NONCE, b"nonce-one")
                .finish(None, false),
                (turn::METHOD_ALLOCATE, true) => siphon_rtp_stun::MessageBuilder::new(
                    turn::message_type(turn::METHOD_ALLOCATE, turn::CLASS_SUCCESS),
                    &id,
                )
                .attribute(
                    turn::ATTR_XOR_RELAYED_ADDRESS,
                    &turn::xor_address_value(relayed, &id),
                )
                .attribute(turn::ATTR_LIFETIME, &turn::lifetime_value(600))
                .finish(None, false),
                (method, _) => siphon_rtp_stun::MessageBuilder::new(
                    turn::message_type(method, turn::CLASS_SUCCESS),
                    &id,
                )
                .finish(None, false),
            };
            let _ = socket.send_to(&response, from).await;
        }
    });
    (server_addr, relayed)
}

fn turn_config(server: SocketAddr) -> TurnServerConfig {
    TurnServerConfig {
        server,
        username: TURN_USER.to_string(),
        password: TURN_PASSWORD.to_string(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ice_offer_gathers_and_advertises_a_relayed_candidate() {
    // The whole point of the TURN client: a leg behind a NAT it cannot be addressed through
    // still offers a reachable candidate. Drives the real allocation exchange over a socket.
    let (turn_addr, relayed) = fake_turn_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_turn_server(turn_config(turn_addr));
    let (_phone_a, addr_a) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "relayed".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let rewritten = ok_sdp_text(&offer);

    assert!(
        rewritten.contains("typ relay"),
        "the offer advertises a relayed candidate: {rewritten}"
    );
    assert!(
        rewritten.contains(&relayed.ip().to_string()),
        "the relayed candidate carries the address the server assigned: {rewritten}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dead_turn_server_costs_a_bounded_delay_and_a_host_only_list() {
    // A relay that never answers must not fail or hang the call — it degrades to the candidates
    // we could gather, exactly like a dead STUN server.
    let dead: SocketAddr = "192.0.2.9:3478".parse().expect("addr");
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_turn_server(turn_config(dead));
    let (_phone_a, addr_a) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "no-relay".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let rewritten = ok_sdp_text(&offer);

    assert!(
        !rewritten.contains("typ relay"),
        "the call still succeeds, but with no relayed candidate: {rewritten}"
    );
    assert!(
        rewritten.contains("typ host"),
        "the host candidate is still offered: {rewritten}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_relayed_candidate_is_advertised_without_a_turn_server() {
    // The default posture for a directly-addressable engine: a relay adds a hop and no
    // reachability, so it is not gathered at all and costs nothing.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "plain".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    assert!(!ok_sdp_text(&offer).contains("typ relay"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conference_join_carrying_ice_is_accepted_and_answers_with_our_own_ice() {
    // It used to be refused outright. The answer must re-originate ICE — our credentials and our
    // gathered candidate — not echo the participant's.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone, addr_a) = phone().await;

    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "ice-room".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                role: Default::default(),
                profile: Default::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&joined);
    let parsed = sdp::parse(&answer).expect("parse conference answer");
    assert!(parsed.is_ice(), "the answer carries ICE: {answer}");
    assert!(
        !answer.contains(A_UFRAG),
        "the seat advertises its own credentials, never the participant's: {answer}"
    );
    assert!(
        answer.contains("a=candidate:"),
        "the seat advertises a gathered candidate: {answer}"
    );
    assert_eq!(engine.conference().participant_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ice_lite_conference_seat_mixes_only_a_stun_validated_source() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_codec::Decoder as _;
    use siphon_rtp_dsp::EnergyVad;
    use siphon_rtp_media::rtp::RtpPacket;

    // An **ice-lite** seat (the default posture — no `--ice full`) takes its seat with the
    // signalled-source gate open, because a connectivity check legitimately arrives from a
    // peer-reflexive transport the SDP never carried (RFC 8445 §7.3.1.3). Nothing in the room
    // closes that window again: `ice_pending` is only set for a full agent, and no selection is
    // coming that would narrow the gate. What must close it is the datapath's layer-4 ICE gate
    // on the redirected path — media reaches the room only from the source a check validated.
    // Without it, anyone who can reach the seat's port injects audio into the mix every other
    // participant hears: RTPBleed on a conference seat.
    // docs/security-and-nat.md §4 layer 4; RFC 8445 §7.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    // A plain listener seat, so the room has somewhere to send whatever it mixed.
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 1)).await;
    let joined_a = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "lite-room".into(),
                from_tag: "alice".into(),
                sdp: sdp_for(addr_a, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_a = sdp::parse(&ok_sdp_text(&joined_a))
        .expect("A answer")
        .remote_rtp;

    // The ICE seat. The engine has no full agent, so this is the datapath's ice-lite responder.
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let joined_b = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "lite-room".into(),
                from_tag: "bob".into(),
                sdp: ice_offer_with_candidate(addr_b),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer_b = sdp::parse(&ok_sdp_text(&joined_b)).expect("B answer");
    let engine_b = answer_b.remote_rtp;
    let engine_ufrag = answer_b.ice_ufrag.clone().expect("seat ufrag");
    let engine_pwd = answer_b.ice_pwd.clone().expect("seat pwd");

    // An off-path attacker sprays the seat's port with full-scale µ-law, never having answered
    // (or sent) a single connectivity check.
    let (attacker, _) = phone_at(Ipv4Addr::new(127, 0, 0, 9)).await;
    for sequence in 0..30 {
        attacker
            .send_to(&g711_rtp(0, sequence, 0x0EEE_0EEE, 0x00), engine_b)
            .await
            .expect("attacker send");
    }

    let mut decoder = G711::ulaw();
    let mut pcm = vec![0i16; 320];
    let mut loudest = 0i64;
    for _ in 0..15 {
        let (mix, from) = recv(&phone_a).await;
        assert_eq!(from, engine_a, "A hears the mix from its engine port");
        let packet = RtpPacket::parse(&mix).expect("A egress RTP");
        let samples = decoder.decode(packet.payload, &mut pcm).expect("decode");
        loudest = loudest.max(EnergyVad::energy(&pcm[..samples]));
    }
    assert!(
        loudest < 1_000_000,
        "an unvalidated source must never be mixed into the room (loudest frame {loudest})"
    );

    // Positive control: the real participant validates its path with a connectivity check, and
    // from then on its audio is mixed exactly as before — the gate narrows the seat, it does not
    // close it.
    let username = format!("{engine_ufrag}:{A_UFRAG}");
    let check = siphon_rtp_stun::binding_request(&[5u8; 12], &username, engine_pwd.as_bytes());
    phone_b.send_to(&check, engine_b).await.expect("send check");
    // The seat is already receiving the room's 20 ms egress on this socket, so skip past the
    // mix frames to the Binding success response.
    let mut buffer = [0u8; 2048];
    let mut answered = false;
    for _ in 0..25 {
        let (len, _) = timeout(Duration::from_secs(1), phone_b.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("datagram");
        if let Ok(response) = siphon_rtp_stun::parse(&buffer[..len]) {
            assert_eq!(response.message_type, siphon_rtp_stun::BINDING_SUCCESS);
            answered = true;
            break;
        }
    }
    assert!(answered, "the ice-lite responder answers the seat's check");

    for sequence in 0..30 {
        phone_b
            .send_to(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0x00), engine_b)
            .await
            .expect("b send");
    }
    let mut heard_loud = false;
    for _ in 0..25 {
        let (mix, _) = recv(&phone_a).await;
        let packet = RtpPacket::parse(&mix).expect("A egress RTP");
        let samples = decoder.decode(packet.payload, &mut pcm).expect("decode");
        if EnergyVad::energy(&pcm[..samples]) > 1_000_000 {
            heard_loud = true;
            break;
        }
    }
    assert!(
        heard_loud,
        "the validated participant's audio is still mixed into the room"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_ice_conference_seat_opens_its_media_path_only_after_a_pair_is_selected() {
    // The end-to-end proof for a *room* seat: a real peer agent runs against the engine's, and
    // the room neither mixes the seat's audio nor sends it the mix until ICE has chosen. The
    // room — not a forward rule — owns this seat's egress, so the selection has to reach the
    // room actor as well as the datapath.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    let (phone_a, addr_a) = phone().await;

    let joined = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "ice-room".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(addr_a),
                role: Default::default(),
                profile: Default::default(),
            },
        )
        .await;
    let answer = sdp::parse(&ok_sdp_text(&joined)).expect("parse conference answer");
    let seat_endpoint = engine
        .conference()
        .participant_at_tag("ice-room", "a")
        .expect("the seat is registered");

    // Nothing adopted yet: the seat is gated shut on both directions.
    assert_eq!(engine.datapath().ice_validated_source(seat_endpoint), None);

    // Drive both agents until the engine selects a pair.
    let mut peer = peer_agent(&answer, addr_a);
    let mut buffer = [0u8; 2048];
    let mut now = 0u64;
    while now < 4_000
        && engine
            .datapath()
            .ice_validated_source(seat_endpoint)
            .is_none()
    {
        for action in peer.poll(now) {
            if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                phone_a.send_to(&datagram, to).await.expect("peer send");
            }
        }
        engine.drive_ice_agents(now).await;
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(20), phone_a.recv_from(&mut buffer)).await
        {
            for action in peer.on_datagram(addr_a, from, &buffer[..len], now) {
                if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                    phone_a.send_to(&datagram, to).await.expect("peer send");
                }
            }
            engine.drive_ice_agents(now).await;
        }
        now += 20;
    }

    assert_eq!(
        engine.datapath().ice_validated_source(seat_endpoint),
        Some(addr_a),
        "the seat's agent selected the participant's real transport"
    );
    // The seat is still seated (ICE succeeded, so nothing tore it down).
    assert_eq!(engine.conference().participant_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_ice_conference_seat_is_mixed_once_its_agent_selects_a_pair() {
    use crate::srtp_bridge::run_redirect_dispatcher;
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_codec::Decoder as _;
    use siphon_rtp_dsp::EnergyVad;
    use siphon_rtp_media::rtp::RtpPacket;

    // The other half of the layer-4 gate on the redirected path: it must *narrow* a seat, not
    // close it. A full RFC 8445 agent runs the checklist, the datapath adopts the pair it selects
    // (`Datapath::adopt_source`), and from then on that seat's audio reaches the mix exactly as a
    // plain seat's does. Complements
    // `a_full_ice_conference_seat_opens_its_media_path_only_after_a_pair_is_selected`, which stops
    // at the selection and never sends media through it.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));

    // A plain listener seat, so the room has somewhere to send what it mixed.
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 1)).await;
    let joined_a = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "full-ice-room".into(),
                from_tag: "alice".into(),
                sdp: sdp_for(addr_a, true),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let engine_a = sdp::parse(&ok_sdp_text(&joined_a))
        .expect("A answer")
        .remote_rtp;

    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let joined_b = engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "full-ice-room".into(),
                from_tag: "bob".into(),
                sdp: ice_offer_with_candidate(addr_b),
                role: ConferenceRole::Talker,
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let answer_b = sdp::parse(&ok_sdp_text(&joined_b)).expect("B answer");
    let engine_b = answer_b.remote_rtp;
    let seat_endpoint = engine
        .conference()
        .participant_at_tag("full-ice-room", "bob")
        .expect("the seat is registered");

    // Drive both agents until the engine's selects a pair.
    let mut peer = peer_agent(&answer_b, addr_b);
    let mut buffer = [0u8; 2048];
    let mut now = 0u64;
    while now < 4_000
        && engine
            .datapath()
            .ice_validated_source(seat_endpoint)
            .is_none()
    {
        for action in peer.poll(now) {
            if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                phone_b.send_to(&datagram, to).await.expect("peer send");
            }
        }
        engine.drive_ice_agents(now).await;
        while let Ok(Ok((len, from))) =
            timeout(Duration::from_millis(20), phone_b.recv_from(&mut buffer)).await
        {
            if siphon_rtp_stun::parse(&buffer[..len]).is_err() {
                continue; // the room's mix egress, not a connectivity check
            }
            for action in peer.on_datagram(addr_b, from, &buffer[..len], now) {
                if let siphon_rtp_ice::AgentAction::Send { to, datagram, .. } = action {
                    phone_b.send_to(&datagram, to).await.expect("peer send");
                }
            }
            engine.drive_ice_agents(now).await;
        }
        now += 20;
    }
    assert_eq!(
        engine.datapath().ice_validated_source(seat_endpoint),
        Some(addr_b),
        "the seat's agent selected the participant's real transport"
    );

    // The room has been ticking silence at A for the whole ICE exchange above, so its socket
    // holds a backlog of pre-selection frames. Drain it first: scanning the backlog instead of
    // what B actually sent would look like "the gate blocked it" and make this test a
    // load-dependent coin flip.
    let mut backlog = [0u8; 2048];
    while timeout(Duration::from_millis(5), phone_a.recv_from(&mut backlog))
        .await
        .is_ok()
    {}

    // The selected pair now carries audio all the way into the mix.
    for sequence in 0..30 {
        phone_b
            .send_to(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0x00), engine_b)
            .await
            .expect("b send");
    }
    let mut decoder = G711::ulaw();
    let mut pcm = vec![0i16; 320];
    let mut heard_loud = false;
    for _ in 0..25 {
        let (mix, from) = recv(&phone_a).await;
        assert_eq!(from, engine_a, "A hears the mix from its engine port");
        let packet = RtpPacket::parse(&mix).expect("A egress RTP");
        let samples = decoder.decode(packet.payload, &mut pcm).expect("decode");
        if EnergyVad::energy(&pcm[..samples]) > 1_000_000 {
            heard_loud = true;
            break;
        }
    }
    assert!(
        heard_loud,
        "the selected pair's audio is mixed once ICE has chosen it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_conference_seat_whose_ice_fails_is_removed_rather_than_left_seated() {
    // RFC 8445 §8.1.2. A seat has no `MediaCall` to reap, so the 2-party teardown path does not
    // cover it — leaving it would hold a room open around a participant that can never be
    // reached, with its gate pending forever.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_full_ice();
    // A candidate nothing answers on: TEST-NET-1 (RFC 5737), unroutable from here.
    let unreachable: SocketAddr = "192.0.2.1:40000".parse().expect("addr");
    engine
        .handle(
            CLIENT,
            Command::ConferenceJoin {
                conference_id: "doomed-room".into(),
                from_tag: "a".into(),
                sdp: ice_offer_with_candidate(unreachable),
                role: Default::default(),
                profile: Default::default(),
            },
        )
        .await;
    assert_eq!(engine.conference().participant_count(), 1);

    // Drive past the checklist's failure deadline without ever answering a check.
    let mut now = 0u64;
    while now < 120_000 && engine.conference().participant_count() > 0 {
        engine.drive_ice_agents(now).await;
        now += 500;
    }

    assert_eq!(
        engine.conference().participant_count(),
        0,
        "the unreachable seat is dropped when its checklist fails"
    );
    assert_eq!(
        engine.conference().room_count(),
        0,
        "and the room it was alone in is torn down with it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_ice_is_off_by_default_and_keeps_the_lite_responder() {
    // Without `--ice full` the datapath still answers checks itself and adopts the validated
    // source, exactly as before — no behaviour change for existing deployments.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    ice_call_with_validated_a(
        &engine,
        CLIENT,
        "lite-default",
        &phone_a,
        ice_offer_with_candidate(addr_a),
        addr_b,
    )
    .await;
    let near_rtp = engine
        .calls
        .get("lite-default")
        .map(|call| call.near.rtp.id)
        .expect("call");
    assert_eq!(
        engine.datapath().ice_validated_source(near_rtp),
        Some(addr_a),
        "the datapath responder adopted the source, as an ice-lite agent does"
    );
    // And the driver is inert.
    assert!(engine.drive_ice_agents(0).await.is_empty());
}

// ---- RFC 7675 consent freshness (end-to-end over the real datapath) --------------------------

/// A's ICE credentials in the consent tests.
const A_UFRAG: &str = "AAAAAA";

const A_PWD: &str = "apasswordapasswordapas";

/// Consent tuned for a short test: probe every tick, declare death after 6 ticks.
fn test_consent() -> crate::ice::driver::ConsentConfig {
    crate::ice::driver::ConsentConfig {
        interval_ticks: 1,
        timeout_ticks: 6,
        rto_ticks: 1,
    }
}

/// An ICE offer from A at the socket it will actually send from.
fn ice_offer_from(addr: SocketAddr) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             a=ice-ufrag:{A_UFRAG}\r\na=ice-pwd:{A_PWD}\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
        ip = addr.ip(),
        port = addr.port()
    )
}

/// Offer + answer an ICE call (A offers ICE, B answers plain), then have A run one valid
/// connectivity check so the datapath adopts its source as the validated path. Returns the
/// engine's A-facing address (where A sends) and the engine's own advertised credentials.
async fn ice_call_with_validated_a(
    engine: &Engine<UdpLoopbackDatapath>,
    client: ClientId,
    call_id: &str,
    phone_a: &UdpSocket,
    offer_sdp: String,
    answer_addr: SocketAddr,
) -> SocketAddr {
    let offer = engine
        .handle(
            client,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: offer_sdp,
                profile: Default::default(),
            },
        )
        .await;
    let _ = ok_sdp_text(&offer);
    let answer = engine
        .handle(
            client,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(answer_addr, false),
                profile: Default::default(),
            },
        )
        .await;
    let answer_out = ok_sdp_text(&answer);
    let near = sdp::parse(&answer_out).expect("parse engine answer");
    let engine_ufrag = near.ice_ufrag.clone().expect("engine ufrag");
    let engine_pwd = near.ice_pwd.clone().expect("engine pwd");

    // A's connectivity check: this is what makes its source the *validated* path.
    let username = format!("{engine_ufrag}:{A_UFRAG}");
    let check = siphon_rtp_stun::binding_request(&[7u8; 12], &username, engine_pwd.as_bytes());
    phone_a
        .send_to(&check, near.remote_rtp)
        .await
        .expect("send check");
    // Await the engine's answer, so adoption has certainly happened before the test proceeds.
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(1), phone_a.recv_from(&mut buffer))
        .await
        .expect("no timeout")
        .expect("recv response");
    assert_eq!(
        siphon_rtp_stun::parse(&buffer[..len])
            .expect("parse")
            .message_type,
        siphon_rtp_stun::BINDING_SUCCESS
    );
    near.remote_rtp
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consent_probes_the_validated_source_not_the_signalled_address() {
    // The whole reason consent was not wired before: a NATed peer's `c=` is unusable. A signals
    // 127.0.0.2:5000 but really sends from 127.0.0.50 — checks must follow the validated source.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_consent(test_consent());
    let (phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 50)).await;
    let (_phone_b, addr_b) = phone().await;
    assert_ne!(addr_a.ip().to_string(), "127.0.0.2");

    let mut lying = ice_offer_from(addr_a);
    lying = lying.replace(&format!("c=IN IP4 {}", addr_a.ip()), "c=IN IP4 127.0.0.2");
    let engine_near =
        ice_call_with_validated_a(&engine, CLIENT, "nat", &phone_a, lying, addr_b).await;

    engine.datapath().advance_clock(1);
    assert!(
        engine.drive_consent().await.is_empty(),
        "a freshly validated pair is not failed"
    );

    // The check arrives at A's *real* socket, from the engine's A-facing endpoint.
    let mut buffer = [0u8; 2048];
    let (len, from) = timeout(Duration::from_secs(1), phone_a.recv_from(&mut buffer))
        .await
        .expect("a consent check is sent")
        .expect("recv");
    assert_eq!(from, engine_near, "sourced from the leg's own media port");
    let check = siphon_rtp_stun::parse(&buffer[..len]).expect("parse check");
    assert!(check.is_binding_request());
    // RFC 8445 §7.1.2: addressed to A, signed with A's password (not the engine's).
    assert_eq!(
        check.username(),
        Some(format!("{A_UFRAG}:{}", engine_ufrag_of(&engine, "nat")).as_str())
    );
    assert!(
        siphon_rtp_stun::verify_message_integrity(&buffer[..len], A_PWD.as_bytes()),
        "the check is keyed by the peer's password"
    );
}

/// The engine's own ufrag for `call_id` (its ICE identity), for asserting check USERNAMEs.
fn engine_ufrag_of(engine: &Engine<UdpLoopbackDatapath>, call_id: &str) -> String {
    engine
        .calls
        .get(call_id)
        .and_then(|call| call.ice.as_ref().map(|ice| ice.ufrag.clone()))
        .expect("the call has ICE credentials")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consent_tears_the_call_down_when_the_peer_stops_answering() {
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_consent(test_consent());
    let client = ClientId(11);
    let events = engine.register_client(client);
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    ice_call_with_validated_a(
        &engine,
        client,
        "dead",
        &phone_a,
        ice_offer_from(addr_a),
        addr_b,
    )
    .await;
    assert_eq!(engine.session_count(), 1);

    // A never answers another check. Drive the sweep tick by tick; the pair dies at the timeout.
    let mut failed = Vec::new();
    for _ in 0..12 {
        engine.datapath().advance_clock(1);
        failed = engine.drive_consent().await;
        if !failed.is_empty() {
            break;
        }
    }
    assert_eq!(failed, vec!["dead".to_string()], "consent expired");
    assert_eq!(engine.session_count(), 0, "the call's resources are freed");
    assert!(
        engine.consent.as_ref().expect("consent on").is_empty(),
        "no consent state outlives the call"
    );

    // The owner is told, on the same dead-path contract the media-timeout sweep uses, and the CDR
    // records the distinct reason.
    let mut got_timeout = false;
    let mut cdr_reason = None;
    while let Ok(event) = events.try_recv() {
        match event {
            Event::MediaTimeout { call_id, .. } => {
                assert_eq!(call_id, "dead");
                got_timeout = true;
            }
            Event::CallSummary { reason, .. } => cdr_reason = Some(reason),
            _ => {}
        }
    }
    assert!(got_timeout, "the owner is notified the path is dead");
    assert_eq!(cdr_reason.as_deref(), Some("consent_failed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answering_peer_keeps_consent_fresh_past_the_timeout() {
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_consent(test_consent());
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let engine_near = ice_call_with_validated_a(
        &engine,
        CLIENT,
        "alive",
        &phone_a,
        ice_offer_from(addr_a),
        addr_b,
    )
    .await;

    // Run well past the 6-tick window, answering every check exactly as a real ICE agent would
    // (Binding success signed with A's own password — RFC 8445 §7.3).
    for tick in 0..20 {
        engine.datapath().advance_clock(1);
        assert!(
            engine.drive_consent().await.is_empty(),
            "consent must not fail while the peer answers (tick {tick})"
        );
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
        {
            let check = siphon_rtp_stun::parse(&buffer[..len]).expect("parse check");
            if check.is_binding_request() {
                let response = siphon_rtp_stun::binding_success_response(
                    &check.transaction_id,
                    addr_a,
                    Some(A_PWD.as_bytes()),
                );
                phone_a
                    .send_to(&response, engine_near)
                    .await
                    .expect("answer the check");
                // Let the datapath forward it through the full-agent seam before the next tick.
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    assert_eq!(engine.session_count(), 1, "the call is still up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consent_is_off_by_default_and_never_probes() {
    // The RFC 7675 §4 ICE-lite posture: answer checks, never initiate them.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    ice_call_with_validated_a(
        &engine,
        CLIENT,
        "lite",
        &phone_a,
        ice_offer_from(addr_a),
        addr_b,
    )
    .await;

    for _ in 0..12 {
        engine.datapath().advance_clock(1);
        assert!(engine.drive_consent().await.is_empty());
    }
    let mut buffer = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer))
            .await
            .is_err(),
        "an ice-lite agent must not send consent checks"
    );
    assert_eq!(engine.session_count(), 1, "and the call stays up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consent_is_not_started_for_a_leg_whose_peer_never_checks() {
    // No validated pair ⇒ nothing to probe, and crucially nothing to *fail*: a leg the peer has
    // not yet checked must never be torn down by consent (the media-timeout sweep owns that).
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_consent(test_consent());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "silent".into(),
                from_tag: "a".into(),
                sdp: ice_offer_from(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "silent".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile: Default::default(),
            },
        )
        .await;

    for _ in 0..20 {
        engine.datapath().advance_clock(1);
        assert!(
            engine.drive_consent().await.is_empty(),
            "an unvalidated leg is never failed by consent"
        );
    }
    assert_eq!(engine.session_count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_ice_leg_is_probed_with_its_own_peer_credentials() {
    // Both sides ICE: the near leg's checks are signed with A's password and the far leg's with
    // B's. Signing either with the wrong side's password would be rejected by that peer.
    let engine = Engine::new(UdpLoopbackDatapath::new()).with_consent(test_consent());
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    const B_UFRAG: &str = "BBBBBB";
    const B_PWD: &str = "bpasswordbpasswordbpas";

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "both".into(),
                from_tag: "a".into(),
                sdp: ice_offer_from(addr_a),
                profile: Default::default(),
            },
        )
        .await;
    let far_offer = sdp::parse(&ok_sdp_text(&offer)).expect("parse far offer");
    let engine_pwd = far_offer.ice_pwd.clone().expect("engine pwd");
    let engine_ufrag = far_offer.ice_ufrag.clone().expect("engine ufrag");

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "both".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: format!(
                    "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
                         a=ice-ufrag:{B_UFRAG}\r\na=ice-pwd:{B_PWD}\r\n\
                         m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
                    ip = addr_b.ip(),
                    port = addr_b.port()
                ),
                profile: Default::default(),
            },
        )
        .await;
    let near_answer = sdp::parse(&ok_sdp_text(&answer)).expect("parse near answer");

    // Both peers validate their own leg.
    for (phone, engine_addr, ufrag) in [
        (&phone_a, near_answer.remote_rtp, A_UFRAG),
        (&phone_b, far_offer.remote_rtp, B_UFRAG),
    ] {
        let check = siphon_rtp_stun::binding_request(
            &[8u8; 12],
            &format!("{engine_ufrag}:{ufrag}"),
            engine_pwd.as_bytes(),
        );
        phone.send_to(&check, engine_addr).await.expect("check");
        let mut buffer = [0u8; 2048];
        timeout(Duration::from_secs(1), phone.recv_from(&mut buffer))
            .await
            .expect("no timeout")
            .expect("response");
    }

    engine.datapath().advance_clock(1);
    assert!(engine.drive_consent().await.is_empty());

    for (phone, peer_ufrag, peer_pwd) in [(&phone_a, A_UFRAG, A_PWD), (&phone_b, B_UFRAG, B_PWD)] {
        let mut buffer = [0u8; 2048];
        let (len, _) = timeout(Duration::from_secs(1), phone.recv_from(&mut buffer))
            .await
            .expect("each ICE leg is probed")
            .expect("recv");
        let check = siphon_rtp_stun::parse(&buffer[..len]).expect("parse");
        assert_eq!(
            check.username(),
            Some(format!("{peer_ufrag}:{engine_ufrag}").as_str())
        );
        assert!(
            siphon_rtp_stun::verify_message_integrity(&buffer[..len], peer_pwd.as_bytes()),
            "each leg's check is keyed by the password of the peer it faces"
        );
    }
}

/// An SDP whose `c=` claims `ip` (not necessarily where its media actually arrives from).
fn sdp_claiming(ip: &str, port: u16) -> String {
    format!(
        "v=0\r\no=- 1 1 IN IP4 host.invalid\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subnet_source_flag_admits_a_same_24_source() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    // A is signalled as 127.0.0.2 but its media actually arrives from 127.0.0.50 (same /24, e.g.
    // a carrier that re-NATs within a block); B is signalled at its real address.
    let (phone_a, _addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 50)).await;
    let (phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 51)).await;
    let profile = ProfileFlags {
        flags: vec!["subnet-source".to_string()],
        ..Default::default()
    };

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "subnet".into(),
                from_tag: "a".into(),
                sdp: sdp_claiming("127.0.0.2", 5000),
                profile: profile.clone(),
            },
        )
        .await;
    let far = sdp::parse(&ok_sdp_text(&offer)).expect("far");

    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "subnet".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, false),
                profile,
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

    // 127.0.0.50 shares 127.0.0.0/24 with the signalled 127.0.0.2, so the subnet gate accepts it
    // (an exact gate would reject) and A's media relays to B.
    phone_a
        .send_to(&rtp(0x00AB_00AB), near.remote_rtp)
        .await
        .expect("send a");
    let (data, from) = recv(&phone_b).await;
    assert_eq!(data, rtp(0x00AB_00AB));
    assert_eq!(from, far.remote_rtp);
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relayed_rtcp_is_exported_to_the_hep_collector() {
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));

    // Stand in for VoIPmonitor's HEP input with a loopback UDP socket.
    let collector = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind collector");
    let collector_addr = collector.local_addr().expect("collector addr");
    let exporter = HepExporter::connect(collector_addr).await.expect("connect");
    engine.set_hep_export(exporter, 7);
    tokio::spawn(engine.clone().run_rtcp_export());
    // Let the export task enable the RTCP observation tap before any media flows.
    tokio::task::yield_now().await;

    // A muxed call (RTCP rides the RTP port), so one send exercises the path.
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "qos".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let _far = sdp::parse(&ok_sdp_text(&offer)).expect("far");
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "qos".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

    // A sends an RTCP SR through the relay (mux: on the near RTP port).
    let report = vec![0x80u8, 200, 0x00, 0x06, 0x11, 0x22, 0x33, 0x44];
    phone_a
        .send_to(&report, near.remote_rtp)
        .await
        .expect("send rtcp");
    assert_eq!(recv(&phone_b).await.0, report, "RTCP relays to B");

    // The HEP collector receives a HEP3 packet carrying the RTCP, correlated by call-id.
    let mut buffer = [0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(2), collector.recv_from(&mut buffer))
        .await
        .expect("no timeout")
        .expect("recv hep");
    let packet = &buffer[..len];
    assert_eq!(&packet[..4], b"HEP3");
    assert!(
        contains_bytes(packet, &report),
        "HEP carries the relayed RTCP"
    );
    assert!(
        contains_bytes(packet, b"qos"),
        "HEP correlation id = call-id"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relayed_rtcp_reception_report_emits_call_quality_on_the_control_channel() {
    // A 2-party plain-relay call: an inbound RTCP reception report (RFC 3550 §6.4.2) surfaces as
    // an `Event::CallQuality` on the owner's control channel — keyed by `call_id`, carrying the
    // same loss/jitter/MOS the HEP QoS export derives — alongside the unchanged raw-RTCP relay.
    let engine = Arc::new(Engine::new(UdpLoopbackDatapath::new()));
    let events = engine.register_client(CLIENT);

    // Bring up the RTCP export tap (which also pushes the control-channel quality events).
    let collector = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind collector");
    let exporter = HepExporter::connect(collector.local_addr().expect("addr"))
        .await
        .expect("connect");
    engine.set_hep_export(exporter, 7);
    tokio::spawn(engine.clone().run_rtcp_export());
    tokio::task::yield_now().await;

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "quality".into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "quality".into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let near = sdp::parse(&ok_sdp_text(&answer)).expect("near");

    // A compound Receiver Report with one reception block: fraction_lost 13/256, jitter 160 @
    // 8 kHz (= 20 ms). RC=1, PT=201, length 7 words.
    let mut report = vec![0x81u8, 201, 0x00, 0x07];
    report.extend_from_slice(&0xAAAA_0001u32.to_be_bytes()); // reporter ssrc
    report.extend_from_slice(&0x1111_2222u32.to_be_bytes()); // reported-on ssrc
    report.push(13); // fraction lost (13/256 ≈ 5.08 %)
    report.extend_from_slice(&[0x00, 0x00, 0x02]); // cumulative lost
    report.extend_from_slice(&0u32.to_be_bytes()); // extended highest seq
    report.extend_from_slice(&160u32.to_be_bytes()); // jitter
    report.extend_from_slice(&0u32.to_be_bytes()); // LSR
    report.extend_from_slice(&0u32.to_be_bytes()); // DLSR
    phone_a
        .send_to(&report, near.remote_rtp)
        .await
        .expect("send rtcp");
    // The raw RTCP still relays verbatim to B (unchanged passthrough).
    assert_eq!(recv(&phone_b).await.0, report, "RTCP relays to B");

    // ...and the owner receives a CallQuality event derived from the reception block.
    let event = timeout(Duration::from_secs(2), events.recv_async())
        .await
        .expect("no timeout")
        .expect("event");
    match event {
        Event::CallQuality {
            conference_id,
            call_id,
            from_tag,
            jitter_ms,
            loss_percent,
            mos,
        } => {
            assert!(
                conference_id.is_none(),
                "a plain relay carries no conference_id"
            );
            assert_eq!(call_id.as_deref(), Some("quality"), "keyed by call_id");
            assert_eq!(from_tag, "a", "tagged by the reporting (near) leg");
            assert!(
                (loss_percent - (13.0 / 256.0 * 100.0)).abs() < 1e-9,
                "13/256 → 5.08 %, got {loss_percent}"
            );
            assert!(
                (jitter_ms - 20.0).abs() < 1e-9,
                "160 @ 8 kHz → 20 ms, got {jitter_ms}"
            );
            assert!(mos > 1.0 && mos < 4.5, "plausible MOS, got {mos}");
        }
        other => panic!("expected CallQuality, got {other:?}"),
    }
}

/// Offer + answer a plaintext PCMU↔PCMU call on `engine`, optionally requesting echo cancellation.
/// The flag is set on both messages' profiles (as a controller would); the media pipeline is built
/// at answer, so `resolve_pipeline` / `build_direction` read it from the answer profile — exactly
/// how `noise_suppression` and `record_call` are honoured.
async fn offer_answer_aec(
    engine: &Engine<UdpLoopbackDatapath>,
    call_id: &str,
    addr_a: SocketAddr,
    addr_b: SocketAddr,
    echo_cancellation: bool,
) {
    let profile = || ProfileFlags {
        echo_cancellation,
        ..Default::default()
    };
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                sdp: sdp_for(addr_a, true),
                profile: profile(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "a".into(),
                to_tag: "b".into(),
                sdp: sdp_for(addr_b, true),
                profile: profile(),
            },
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_cancellation_promotes_a_same_codec_call_to_the_media_pipeline() {
    // A same-codec (PCMU↔PCMU) call would relay in-kernel (`Passthrough`); the `echo_cancellation`
    // flag must promote it to the userspace media slow path (decode → cancel → re-encode), exactly
    // as `noise_suppression` / `record_call` do — otherwise the flag would be silently dropped on a
    // non-transcoding call (a config knob wired to nothing).
    let (_phone_a, addr_a) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    let (_phone_b, addr_b) = phone_at(Ipv4Addr::new(127, 0, 0, 3)).await;

    // Control: no flag ⇒ the same-codec call stays an in-kernel passthrough (not a media call).
    let plain = Engine::new(UdpLoopbackDatapath::new());
    offer_answer_aec(&plain, "aec-off", addr_a, addr_b, false).await;
    assert!(
        !plain.media().is_media_call("aec-off"),
        "same-codec call without the flag must stay an in-kernel passthrough"
    );

    // With the flag ⇒ promoted to the userspace media pipeline (a transcoding media call), where
    // `Direction::handle` runs the echo canceller on the decoded ingress.
    let cancelled = Engine::new(UdpLoopbackDatapath::new());
    offer_answer_aec(&cancelled, "aec-on", addr_a, addr_b, true).await;
    assert!(
        cancelled.media().is_transcoding_call("aec-on"),
        "the echo_cancellation flag must promote the call to the media slow path where AEC runs"
    );
}

// ---- AnswerLocal: single-leg UAS answer (RFC 3264 §6.1) ----

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_leg_cdr_books_the_callers_media_on_the_callers_own_leg() {
    // A single-leg call has ONE party, so its CDR has one leg record — the caller's — carrying the
    // call's whole packet/byte total *and* its measured quality. It used to emit two: the caller's
    // tag, signalled address and RFC 3550 quality on `near` with `packets_in=0`, and every counter
    // on an untagged `far` with `remote="-"`. `answer_local` advertises the far socket, so all the
    // media lands there while the near leg holds the caller's identity — a consumer joining media
    // CDRs to SIP CDRs could not tell which party the packets belonged to.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let rx = engine.datapath().rx();
    tokio::spawn(run_redirect_dispatcher(
        rx,
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let events = engine.register_client(CLIENT);
    let (phone_a, addr_a) = phone().await;

    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "cdr-single".into(),
                from_tag: "caller".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let advertised = sdp::parse(&ok_sdp_text(&result))
        .expect("answer parses")
        .remote_rtp;

    // The caller streams to the socket the answer advertised and reads the echo back, so both
    // directions of the one stream are accounted. Asymmetric counts would be better still, but the
    // single-leg reflect is 1:1 by construction.
    const FRAMES: u64 = 5;
    for sequence in 0..FRAMES as u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0000_2222, 0xFF), advertised)
            .await
            .expect("caller sends");
        let (_echo, from) = recv(&phone_a).await;
        assert_eq!(
            from, advertised,
            "the echo returns off the advertised socket"
        );
    }

    let deleted = engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "cdr-single".into(),
                from_tag: "caller".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(matches!(deleted, CmdResult::Ok { .. }));

    let mut legs = None;
    while let Ok(event) = events.try_recv() {
        if let Event::CallSummary { legs: summary, .. } = event {
            legs = Some(summary);
        }
    }
    let legs = legs.expect("CallSummary emitted on delete");
    assert_eq!(
        legs.len(),
        1,
        "one party ⇒ one leg record, not a tagged empty leg plus an untagged full one: {legs:?}"
    );
    let caller = &legs[0];
    assert_eq!(caller.tag, "caller", "the sole leg is the caller's");
    assert_eq!(
        caller.packets_in, FRAMES,
        "the caller's sent packets are booked against the caller"
    );
    assert_eq!(
        caller.packets_out, FRAMES,
        "so are the packets the engine sent back to it"
    );
    assert!(caller.bytes_in > 0 && caller.bytes_out > 0, "{caller:?}");
    // The quality half was always attributed correctly — it must stay on the same record as the
    // counters now that there is only one.
    assert_eq!(
        caller.ssrc,
        Some(0x0000_2222),
        "the caller's own SSRC (RFC 3550) rides the same record"
    );
    assert!(caller.jitter_ms.is_some(), "as does its measured jitter");
    assert_eq!(
        caller.codec.as_deref(),
        Some("PCMU"),
        "and the codec the answer negotiated"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_leg_cdr_collapses_even_when_no_media_ever_flowed() {
    // The collapse keys on "no far party was negotiated" (no `to_tag`), not on where the counters
    // happen to be — so an unanswered call that never saw a packet also reports one leg, the
    // caller's, rather than a phantom second party with an empty tag.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let events = engine.register_client(CLIENT);
    let (_phone_a, addr_a) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "cdr-unanswered".into(),
                from_tag: "caller".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "cdr-unanswered".into(),
                from_tag: "caller".into(),
                to_tag: None,
            },
        )
        .await;

    let mut legs = None;
    while let Ok(event) = events.try_recv() {
        if let Event::CallSummary { legs: summary, .. } = event {
            legs = Some(summary);
        }
    }
    let legs = legs.expect("CallSummary emitted on delete");
    assert_eq!(legs.len(), 1, "an unanswered call has one party: {legs:?}");
    assert_eq!(legs[0].tag, "caller");
    assert_eq!(legs[0].packets_in, 0, "no media ever arrived");
}

#[tokio::test]
async fn answer_local_binds_one_leg_and_advertises_the_socket_it_bound() {
    // A locally-answered call has one party, so it binds one socket pair — not a second,
    // never-advertised pair that no packet can reach. `offer`, which may still get a B side, keeps
    // both. Left unchecked this idled half of every IVR / announcement / echo / voice-AI call's
    // ports, halving the capacity of a `--port-min`/`--port-max` range on such a node.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;

    // Muxed: one port for the whole call.
    let muxed = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "one-leg-mux".into(),
                from_tag: "caller".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let advertised = sdp::parse(&ok_sdp_text(&muxed)).expect("answer").remote_rtp;
    {
        let call = engine.calls.get("one-leg-mux").expect("call present");
        assert!(call.far.is_none(), "no B-facing leg is allocated");
        assert_eq!(
            call.endpoint_ids().count(),
            1,
            "one muxed leg ⇒ exactly one bound endpoint"
        );
        assert_eq!(
            call.near.rtp.local_addr, advertised,
            "and it is the socket the answer told the caller to send to"
        );
        assert_eq!(
            call.near.remote_rtp,
            Some(addr_a),
            "that same leg carries the caller's signalled address"
        );
    }

    // Non-muxed: RTP + a companion RTCP port, still for one leg only.
    engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "one-leg-demux".into(),
                from_tag: "caller".into(),
                sdp: sdp_for(addr_a, false),
                profile: Default::default(),
            },
        )
        .await;
    let call = engine.calls.get("one-leg-demux").expect("call present");
    assert!(call.far.is_none());
    assert_eq!(
        call.endpoint_ids().count(),
        2,
        "one non-muxed leg ⇒ RTP + RTCP, and nothing else"
    );
}

#[tokio::test]
async fn answer_local_never_multiplexes_rtcp_the_offer_did_not_ask_for() {
    // RFC 5761 §5.1.1: multiplexing happens only where both ends agreed, and this SDP is an
    // *answer* — so the `rtcp-mux` directive applies with its near-side meaning. `require` used to
    // be read with its far-side meaning here (force mux on the leg we generate), which advertised
    // `a=rtcp-mux` back to a caller that had not offered it: that caller keeps sending RTCP to
    // `port + 1`, which the muxed leg never bound.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;

    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "mux".into(),
                from_tag: "caller".into(),
                // A non-muxed offer (`sdp_for(.., false)` omits `a=rtcp-mux`).
                sdp: sdp_for(addr_a, false),
                profile: ProfileFlags {
                    rtcp_mux: vec!["require".to_string()],
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = ok_sdp_text(&result);
    assert!(
        !answer.contains("a=rtcp-mux"),
        "the answer must not offer mux back to a caller that did not offer it: {answer}"
    );
    // And the leg really did bind the companion RTCP port the caller will use.
    let call = engine.calls.get("mux").expect("call present");
    assert!(
        call.near.rtcp.is_some(),
        "a non-muxed leg binds RTP + a companion RTCP port"
    );
    assert_eq!(
        call.endpoint_ids().count(),
        2,
        "and still only one leg's worth"
    );
}

#[tokio::test]
async fn answer_is_refused_on_a_locally_answered_call() {
    // `answer_local` already sent the answer and the caller is talking to the engine's only socket.
    // Serving an `answer` on top would have to invent a B leg — and pointing B's relay at the
    // caller's own endpoint would break the live call. Refuse, and say why.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "local".into(),
                from_tag: "caller".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let answered = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "local".into(),
                from_tag: "caller".into(),
                to_tag: "callee".into(),
                sdp: sdp_for(addr_b, true),
                profile: Default::default(),
            },
        )
        .await;
    let CmdResult::Error { reason } = answered else {
        panic!("expected an error, got {answered:?}");
    };
    assert!(
        reason.contains("answered locally"),
        "the reason names the cause: {reason}"
    );
    // And the live call is untouched — same single leg, still no to_tag.
    let call = engine
        .calls
        .get("local")
        .expect("call survives the refusal");
    assert!(call.far.is_none());
    assert!(call.to_tag.is_none());
}

#[tokio::test]
async fn checkpoint_is_refused_on_a_single_leg_call() {
    // The HA snapshot is a two-leg record and a standby resumes a two-party relay from it. A
    // single-leg call's "far side" is this engine's own pipeline — not replicable state — so
    // refuse rather than hand back a blob that would restore as a call that never existed.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ivr".into(),
                from_tag: "caller".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let result = engine
        .handle(
            CLIENT,
            Command::Checkpoint {
                call_id: "ivr".into(),
                from_tag: "caller".into(),
            },
        )
        .await;
    let CmdResult::Error { reason } = result else {
        panic!("expected an error, got {result:?}");
    };
    assert!(
        reason.contains("single-leg"),
        "the reason names the cause: {reason}"
    );
}

/// VoLTE-shaped offer: AMR-WB (96) and AMR (97) are the caller's preferred codecs, then G.711
/// (PCMU 0 / PCMA 8), plus the RFC 4733 telephone-event (101). Used to prove the answer selects
/// the first codec this *build* can encode, not one from a hardcoded allow-list.
const VOLTE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 127.0.0.1\r\n",
    "s=-\r\n",
    "c=IN IP4 127.0.0.1\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 96 97 0 8 101\r\n",
    "a=rtpmap:96 AMR-WB/16000\r\n",
    "a=rtpmap:97 AMR/8000\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=ptime:20\r\n",
);

#[cfg(not(feature = "amr"))]
#[tokio::test]
async fn answer_local_volte_offer_answers_only_first_encodable_codec() {
    // Default build (no `amr`): AMR-WB / AMR are decode-only, so the first *encodable* offered
    // codec — PCMU — is the sole answered audio codec, alongside the telephone-event PT.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-volte".into(),
                from_tag: "tag-a".into(),
                sdp: VOLTE_OFFER.into(),
                profile: Default::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&result);
    assert!(
        answer.contains("RTP/AVP 0 101"),
        "m=audio must list only PCMU (0) + telephone-event (101): {answer}"
    );
    assert!(answer.contains("a=rtpmap:0 PCMU/8000"), "{answer}");
    assert!(
        answer.contains("a=rtpmap:101 telephone-event/8000"),
        "{answer}"
    );
    assert!(
        !answer.contains("AMR"),
        "the AMR / AMR-WB rtpmaps must be gone from the answer: {answer}"
    );

    // The transcoder is engaged now: a single-leg processing MediaCall answering in PCMU.
    assert!(
        engine.media().is_transcoding_call("al-volte"),
        "answer_local must promote the single leg to a processing MediaCall"
    );
    let call = engine.calls.get("al-volte").expect("call present");
    assert_eq!(call.pipeline, PipelineKind::Media);
    let far = call.far_codec.as_ref().expect("far codec chosen");
    assert_eq!(far.encoding_name, "PCMU");
    assert_eq!(far.payload_type, 0);
}

#[tokio::test]
async fn answer_local_pcma_only_offer_answers_pcma() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 127.0.0.1\r\n",
        "s=-\r\n",
        "c=IN IP4 127.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 8 101\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
        "a=ptime:20\r\n",
    );
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-pcma".into(),
                from_tag: "tag-a".into(),
                sdp: offer.into(),
                profile: Default::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&result);
    assert!(answer.contains("RTP/AVP 8 101"), "{answer}");
    assert!(answer.contains("a=rtpmap:8 PCMA/8000"), "{answer}");
    assert!(
        answer.contains("a=rtpmap:101 telephone-event/8000"),
        "{answer}"
    );
    let call = engine.calls.get("al-pcma").expect("call present");
    let far = call.far_codec.as_ref().expect("far codec chosen");
    assert_eq!(far.encoding_name, "PCMA");
    assert_eq!(far.payload_type, 8);
}

#[tokio::test]
async fn answer_local_negotiates_offered_comfort_noise() {
    // The offer carries RFC 3389 comfort noise (static PT 13). The single-leg answer negotiates it
    // back (m-line + rtpmap) so the leg can send real CN during idle gaps instead of self-echo,
    // and the CN PT is recorded on the call for the promoted media actor.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 127.0.0.1\r\n",
        "s=-\r\n",
        "c=IN IP4 127.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0 13 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
        "a=ptime:20\r\n",
    );
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-cn".into(),
                from_tag: "tag-a".into(),
                sdp: offer.into(),
                profile: Default::default(),
            },
        )
        .await;
    let answer = ok_sdp_text(&result);
    // The answer advertises the engine's own port, so match the format list, not the port.
    assert!(
        answer.contains("RTP/AVP 0 101 13"),
        "CN (PT 13) negotiated in the answer format list: {answer}"
    );
    assert!(
        answer.contains("a=rtpmap:13 CN/8000"),
        "CN rtpmap advertised: {answer}"
    );
    let call = engine.calls.get("al-cn").expect("call present");
    assert_eq!(
        call.comfort_noise_payload_type,
        Some(13),
        "the negotiated CN PT is recorded for the comfort-idle egress"
    );
}

#[cfg(not(feature = "amr"))]
#[tokio::test]
async fn answer_local_amr_only_offer_is_rejected_no_encodable_codec() {
    // Only AMR-WB (decode-only in the default build) + telephone-event: nothing is encodable, so
    // the answer is refused with the exact reason the SIPhon side maps to SIP 488, and the
    // half-built session is torn down (ports freed, gone from the registry).
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 127.0.0.1\r\n",
        "s=-\r\n",
        "c=IN IP4 127.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 96 101\r\n",
        "a=rtpmap:96 AMR-WB/16000\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
    );
    let result = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-amr".into(),
                from_tag: "tag-a".into(),
                sdp: offer.into(),
                profile: Default::default(),
            },
        )
        .await;
    match result {
        CmdResult::Error { reason } => assert_eq!(reason, "no-encodable-codec"),
        other => panic!("expected no-encodable-codec error, got {other:?}"),
    }
    assert!(
        engine.calls.get("al-amr").is_none(),
        "the half-built session must be torn down on reject"
    );
    assert_eq!(engine.session_count(), 0, "no session leaks on reject");
}

#[tokio::test]
async fn answer_local_preserves_telephone_event_and_ptime() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let offer = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 127.0.0.1\r\n",
        "s=-\r\n",
        "c=IN IP4 127.0.0.1\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
        "a=ptime:30\r\n",
    );
    let answer = ok_sdp_text(
        &engine
            .handle(
                CLIENT,
                Command::AnswerLocal {
                    call_id: "al-ptime".into(),
                    from_tag: "tag-a".into(),
                    sdp: offer.into(),
                    profile: Default::default(),
                },
            )
            .await,
    );
    assert!(
        answer.contains("a=rtpmap:101 telephone-event/8000"),
        "telephone-event PT must be kept on a successful answer: {answer}"
    );
    assert!(
        answer.contains("a=ptime:30"),
        "the offered 30 ms ptime must be preserved: {answer}"
    );
}

#[tokio::test]
async fn answer_local_then_delete_drains_the_registry() {
    // Leak/teardown: a single-leg answer registers a session; delete drains it back to baseline.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let ok = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "al-drain".into(),
                from_tag: "tag-a".into(),
                sdp: VOLTE_OFFER.into(),
                profile: Default::default(),
            },
        )
        .await;
    assert!(matches!(ok, CmdResult::Ok { .. }), "answer ok: {ok:?}");
    assert!(
        engine.calls.get("al-drain").is_some(),
        "call present after answer"
    );
    assert_eq!(engine.session_count(), 1);

    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "al-drain".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert!(
        engine.calls.get("al-drain").is_none(),
        "the session must drain from the registry on delete"
    );
    assert_eq!(engine.session_count(), 0, "registry drains to baseline");
}

#[cfg(feature = "amr")]
#[tokio::test]
async fn answer_local_volte_offer_answers_amr_wb_with_the_amr_feature() {
    // With the `amr` build feature the engine *can* encode AMR-WB, so the caller-preferred codec
    // (96, first in the offer) wins — proving the pick is `encoder_for`-driven, not a hardcoded
    // exclusion of AMR.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let answer = ok_sdp_text(
        &engine
            .handle(
                CLIENT,
                Command::AnswerLocal {
                    call_id: "al-amr-wb".into(),
                    from_tag: "tag-a".into(),
                    sdp: VOLTE_OFFER.into(),
                    profile: Default::default(),
                },
            )
            .await,
    );
    assert!(answer.contains("RTP/AVP 96 101"), "{answer}");
    assert!(answer.contains("a=rtpmap:96 AMR-WB/16000"), "{answer}");
    assert!(
        !answer.contains("PCMU"),
        "AMR-WB is caller-preferred and wins over G.711: {answer}"
    );
    let call = engine.calls.get("al-amr-wb").expect("call present");
    let far = call.far_codec.as_ref().expect("far codec chosen");
    assert_eq!(far.encoding_name, "AMR-WB");
    assert_eq!(far.payload_type, 96);
}

// ---------------------------------------------------------------------------------------------
// WebSocket tee (send-only audio streaming on a *relaying* call)
// ---------------------------------------------------------------------------------------------

/// A local WebSocket server for tee tests: accepts one connection and republishes every frame it
/// receives on the returned channel. Returns `(uri, frames)`.
async fn tee_server() -> (
    String,
    flume::Receiver<tokio_tungstenite::tungstenite::Message>,
) {
    use futures_util::StreamExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind tee ws");
    let addr = listener.local_addr().expect("tee ws addr");
    let (sender, receiver) = flume::unbounded();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept tee ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("tee ws handshake");
        let (_sink, mut source) = socket.split();
        while let Some(Ok(message)) = source.next().await {
            if sender.send(message).is_err() {
                break;
            }
        }
    });
    (format!("ws://{addr}/tee"), receiver)
}

/// Drain the tee stream until the first binary (audio) frame, returning its bytes.
async fn next_tee_audio(
    frames: &flume::Receiver<tokio_tungstenite::tungstenite::Message>,
) -> Vec<u8> {
    use tokio_tungstenite::tungstenite::Message;
    for _ in 0..40 {
        let message = timeout(Duration::from_secs(3), frames.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        if let Message::Binary(bytes) = message {
            return bytes.to_vec();
        }
    }
    panic!("no binary tee frame arrived");
}

/// Assert the tee's first frame is a send-only `start`, and return its announced format.
async fn expect_tee_start(
    frames: &flume::Receiver<tokio_tungstenite::tungstenite::Message>,
) -> siphon_rtp_media::bridge::protocol::StartData {
    use siphon_rtp_media::bridge::protocol::{ControlMessage, Direction as WsProtoDirection};
    use tokio_tungstenite::tungstenite::Message;
    let first = timeout(Duration::from_secs(3), frames.recv_async())
        .await
        .expect("no timeout")
        .expect("a frame");
    match first {
        Message::Text(text) => match ControlMessage::from_json(text.as_str()) {
            Ok(ControlMessage::Start(data)) => {
                assert_eq!(
                    data.direction,
                    WsProtoDirection::Send,
                    "a tee announces itself send-only"
                );
                data
            }
            other => panic!("expected start, got {other:?}"),
        },
        other => panic!("expected a start text frame, got {other:?}"),
    }
}

/// Stand up a plain two-party G.711 relay through the control plane and return both phones, both
/// engine-facing addresses, and a live engine with the redirect dispatcher running.
async fn two_party_relay(
    call_id: &str,
) -> (
    Engine<UdpLoopbackDatapath>,
    (UdpSocket, SocketAddr),
    (UdpSocket, SocketAddr),
) {
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

    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let far_addr = sdp::parse(&ok_sdp_text(&offer))
        .expect("offer reply")
        .remote_rtp;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: call_id.into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;
    (engine, (phone_a, near_addr), (phone_b, far_addr))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ws_tee_streams_both_legs_as_stereo_while_the_relay_keeps_running() {
    // The headline: a tee is *additive*. A plain two-party G.711 relay is promoted to userspace,
    // both legs' decoded audio is interleaved as stereo L16 to the WS server, AND each peer keeps
    // receiving the other's media — asserted on both the WS frames and the peers' received RTP.
    let (engine, (phone_a, near_addr), (phone_b, far_addr)) = two_party_relay("tee-stereo").await;
    assert!(
        !engine.media().is_media_call("tee-stereo"),
        "a plain relay starts on the in-kernel fast path"
    );

    let (uri, frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "tee-stereo".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Both,
                channels: Some(2),
                sample_rate: None,
            },
        )
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach: {attached:?}"
    );
    assert!(
        engine.media().is_media_call("tee-stereo"),
        "attaching a tee promotes the relay into the userspace media pipeline"
    );

    let start = expect_tee_start(&frames).await;
    assert_eq!(start.media.channels, 2, "stereo caller/callee");
    assert_eq!(start.media.sample_rate, 8000);
    assert_eq!(start.tracks, vec!["inbound", "outbound"]);

    // Both parties talk. Each peer must still receive the other's media (the relay is untouched),
    // and the tee must produce interleaved stereo frames.
    let mut stereo_frame = None;
    for sequence in 0..12u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
        phone_b
            .send_to(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0xFF), far_addr)
            .await
            .expect("b send");
        if stereo_frame.is_none() {
            if let Ok(Ok(bytes)) = timeout(Duration::from_millis(300), async {
                Ok::<_, ()>(next_tee_audio(&frames).await)
            })
            .await
            {
                stereo_frame = Some(bytes);
            }
        }
    }
    let bytes = stereo_frame.expect("a stereo tee frame arrived");
    assert_eq!(
        bytes.len(),
        640,
        "8 kHz / 20 ms stereo L16 = 2 channels x 160 samples x 2 bytes"
    );

    // The relay itself never stopped: each peer receives the other's stream.
    let (to_b, _) = recv(&phone_b).await;
    assert!(
        !to_b.is_empty(),
        "B still receives A's media through the tee'd call"
    );
    let (to_a, _) = recv(&phone_a).await;
    assert!(
        !to_a.is_empty(),
        "A still receives B's media through the tee'd call"
    );

    // Detach demotes the relay back to the in-kernel fast path, and media keeps flowing.
    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsTee {
                call_id: "tee-stereo".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "detach: {detached:?}"
    );
    assert!(
        !engine.media().is_media_call("tee-stereo"),
        "detaching the last tee demotes the relay back to the kernel Forward path"
    );
    phone_a
        .send_to(&g711_rtp(0, 99, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let (after_detach, _) = recv(&phone_b).await;
    assert!(
        !after_detach.is_empty(),
        "the call keeps relaying after the tee is gone"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_only_ws_tee_streams_the_monologue_as_mono() {
    let (engine, (phone_a, near_addr), _b) = two_party_relay("tee-mono").await;
    let (uri, frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "tee-mono".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
            },
        )
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach: {attached:?}"
    );

    let start = expect_tee_start(&frames).await;
    assert_eq!(start.media.channels, 1, "a single-leg tee is mono");
    assert_eq!(start.tracks, vec!["inbound"], "only the caller's track");

    // Only A talks — a caller-only tee must still produce frames (no waiting on the silent callee).
    for sequence in 0..6u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    let bytes = next_tee_audio(&frames).await;
    assert_eq!(bytes.len(), 320, "8 kHz / 20 ms mono L16");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ws_tee_and_a_siprec_subscription_coexist_on_the_same_leg() {
    // A tee attaches where SIPREC attaches (the post-decode fan-out). Detaching the tee must remove
    // *only* the tee's sink: the SRS keeps receiving the subscribed monologue afterwards.
    let (engine, (phone_a, near_addr), _b) = two_party_relay("tee-siprec").await;
    let (srs, srs_addr) = phone().await;

    let subscribe = engine
        .handle(
            CLIENT,
            Command::SubscribeRequest {
                call_id: "tee-siprec".into(),
                from_tags: vec!["tag-a".into()],
                sdp: None,
                profile: Default::default(),
            },
        )
        .await;
    let subscription_tag = match subscribe {
        CmdResult::Ok {
            to_tag: Some(to_tag),
            ..
        } => to_tag,
        other => panic!("expected a subscription to_tag, got {other:?}"),
    };
    let answered = engine
        .handle(
            CLIENT,
            Command::SubscribeAnswer {
                call_id: "tee-siprec".into(),
                from_tag: "tag-a".into(),
                to_tag: subscription_tag,
                sdp: sdp_single_codec(srs_addr, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    assert!(
        matches!(answered, CmdResult::Ok { .. }),
        "subscribe_answer: {answered:?}"
    );

    let (uri, frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "tee-siprec".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
            },
        )
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach: {attached:?}"
    );
    expect_tee_start(&frames).await;

    // A talks: the SRS gets the SIPREC copy and the WS server gets the teed PCM.
    for sequence in 0..6u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    let (to_srs, _) = recv(&srs).await;
    assert!(!to_srs.is_empty(), "the SRS receives the SIPREC fork");
    assert_eq!(
        next_tee_audio(&frames).await.len(),
        320,
        "and the tee streams too"
    );

    // Detach the tee only — the subscription's fork must survive (tagged removal).
    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsTee {
                call_id: "tee-siprec".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "detach: {detached:?}"
    );
    assert!(
        engine.media().is_media_call("tee-siprec"),
        "the subscription still holds the relay in userspace"
    );
    for sequence in 10..16u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    let (still_recording, _) = recv(&srs).await;
    assert!(
        !still_recording.is_empty(),
        "detaching the tee must not tear down the SIPREC fork on the same leg"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ws_tee_server_that_never_reads_does_not_stall_the_call() {
    // The hot-path contract: a stalled consumer drops tee frames, it never blocks the media actor.
    // The server here completes the WebSocket handshake and then never reads a byte.
    let (engine, (phone_a, near_addr), (phone_b, _far)) = two_party_relay("tee-stall").await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled ws");
    let stalled_addr = listener.local_addr().expect("addr");
    let stalled = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        // Hold the socket open forever without reading a single frame.
        std::future::pending::<()>().await;
        drop(socket);
    });

    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "tee-stall".into(),
                from_tag: "tag-a".into(),
                ws_uri: format!("ws://{stalled_addr}/tee"),
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
            },
        )
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach: {attached:?}"
    );

    // Push far more frames than any buffer holds; B must keep receiving every one of them.
    let mut relayed = 0;
    for sequence in 0..200u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
        if timeout(Duration::from_millis(200), async {
            let mut buffer = [0u8; 2048];
            phone_b.recv_from(&mut buffer).await
        })
        .await
        .is_ok()
        {
            relayed += 1;
        }
    }
    assert!(
        relayed >= 190,
        "the call must keep relaying at full rate past a stalled tee consumer (relayed {relayed}/200)"
    );
    stalled.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attaching_a_ws_tee_to_a_websocket_takeover_call_is_rejected() {
    // Takeover (`ws_uri`) routes leg A's media to its own server and never wires A<->B, so there is
    // no relay path to tee. Reject clearly rather than attaching a sink that would never fire.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let ws_addr = listener.local_addr().expect("ws addr");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let _socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        std::future::pending::<()>().await;
    });

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (_phone_a, addr_a) = phone().await;
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "tee-takeover".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(format!("ws://{ws_addr}/stream")),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "ws offer: {offer:?}");

    let (uri, _frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "tee-takeover".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
            },
        )
        .await;
    match attached {
        CmdResult::Error { reason } => assert!(
            reason.contains("takeover"),
            "expected a takeover-conflict error, got {reason}"
        ),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ws_tee_is_refused_while_a_pcap_recording_holds_the_relay_forward_only() {
    // A pcap recording promotes the relay *forward-only* (no decode). Attaching a tee would have to
    // rebuild the actor, which cannot carry the live capture channel across — so refuse rather than
    // silently stop recording. (Attaching the tee first works: `start_recording` then reuses the
    // already-decoding actor.)
    let directory = tempfile::tempdir().expect("tempdir");
    let (engine, (_phone_a, _near), _b) = two_party_relay("tee-vs-pcap").await;
    let started = engine
        .handle(
            CLIENT,
            Command::StartRecording {
                call_id: "tee-vs-pcap".into(),
                from_tag: "tag-a".into(),
                recording_dir: Some(directory.path().to_string_lossy().into_owned()),
                format: None,
                direction: None,
                channels: None,
                max_duration_ms: None,
                silence_ms: None,
                path: None,
            },
        )
        .await;
    assert!(
        matches!(started, CmdResult::Ok { .. }),
        "start_recording: {started:?}"
    );

    let (uri, _frames) = tee_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "tee-vs-pcap".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
            },
        )
        .await;
    match attached {
        CmdResult::Error { reason } => assert!(
            reason.contains("pcap recording"),
            "expected the recording conflict to be named, got {reason}"
        ),
        other => panic!("expected an error, got {other:?}"),
    }
    assert_eq!(
        engine.ws_tee_count(),
        0,
        "the refused attach left no tee behind"
    );
    assert!(
        engine.media().is_relay_call("tee-vs-pcap"),
        "the recording's forward-only actor is untouched by the refusal"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_on_a_ws_takeover_call_does_not_wire_the_relay_to_leg_b() {
    // Establishes the single-leg -> two-party question rather than assuming it: a WS-takeover call
    // allocates leg B's endpoints at offer/answer, so it *looks* like a later `answer` might bridge
    // the caller to a second party. It does not. `answer` short-circuits on `PipelineKind::Ws` and
    // returns the rewritten SDP without installing any A<->B path, so the caller's media continues
    // to the WS server only and B receives nothing.
    //
    // Handing a WS-bridged caller to a real leg B therefore needs a new transition (detach the
    // bridge, wire the relay, keep leg A's ports and SSRC continuous so no re-INVITE is required) —
    // it is not an emergent property of the current answer path.
    use crate::srtp_bridge::run_redirect_dispatcher;
    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let ws_addr = ws_listener.local_addr().expect("ws addr");
    tokio::spawn(async move {
        use futures_util::StreamExt;
        let (stream, _) = ws_listener.accept().await.expect("accept");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("handshake");
        let (_sink, mut source) = socket.split();
        while let Some(Ok(_frame)) = source.next().await {}
    });

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let (phone_b, addr_b) = phone().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-then-answer".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(format!("ws://{ws_addr}/stream")),
                    ..Default::default()
                },
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ws-then-answer".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("the answer still returns SDP")
        .remote_rtp;
    assert!(
        engine.ws().is_ws_call("ws-then-answer"),
        "the call is still WS-bridged after the answer"
    );
    assert!(
        !engine.media().is_media_call("ws-then-answer"),
        "no media pipeline was stood up, so there is no A<->B path"
    );

    // A's media goes to the WS server; B — although its ports are allocated and its answer was
    // accepted — receives nothing.
    for sequence in 0..10u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    let mut buffer = [0u8; 2048];
    assert!(
        timeout(Duration::from_millis(300), phone_b.recv_from(&mut buffer))
            .await
            .is_err(),
        "a WS-takeover call must not relay to leg B (the transition is unimplemented, not implicit)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detaching_a_ws_tee_on_a_call_without_one_is_a_noop() {
    let (engine, _a, _b) = two_party_relay("tee-none").await;
    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsTee {
                call_id: "tee-none".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "idempotent detach"
    );
    let unknown = engine
        .handle(
            CLIENT,
            Command::DetachWsTee {
                call_id: "nope".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(unknown, CmdResult::Error { .. }),
        "unknown call still errors"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repeated_ws_tee_attach_detach_cycles_leave_no_residue() {
    // Leak soak: every attach/detach cycle must return the engine to its starting shape — no tee
    // rows retained, the relay demoted back to the kernel fast path, and media still flowing.
    let (engine, (phone_a, near_addr), (phone_b, _far)) = two_party_relay("tee-soak").await;
    for cycle in 0..8 {
        let (uri, frames) = tee_server().await;
        let attached = engine
            .handle(
                CLIENT,
                Command::AttachWsTee {
                    call_id: "tee-soak".into(),
                    from_tag: "tag-a".into(),
                    ws_uri: uri,
                    direction: WsTeeDirection::Caller,
                    channels: None,
                    sample_rate: None,
                },
            )
            .await;
        assert!(
            matches!(attached, CmdResult::Ok { .. }),
            "cycle {cycle} attach: {attached:?}"
        );
        assert_eq!(engine.ws_tee_count(), 1, "exactly one tee per call");
        expect_tee_start(&frames).await;

        phone_a
            .send_to(&g711_rtp(0, cycle as u16, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");

        let detached = engine
            .handle(
                CLIENT,
                Command::DetachWsTee {
                    call_id: "tee-soak".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await;
        assert!(
            matches!(detached, CmdResult::Ok { .. }),
            "cycle {cycle} detach: {detached:?}"
        );
        assert_eq!(
            engine.ws_tee_count(),
            0,
            "cycle {cycle} left a tee row behind"
        );
        assert!(
            !engine.media().is_media_call("tee-soak"),
            "cycle {cycle} left the relay promoted in userspace"
        );
    }

    // The call is untouched by the churn.
    phone_a
        .send_to(&g711_rtp(0, 500, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let (relayed, _) = recv(&phone_b).await;
    assert!(
        !relayed.is_empty(),
        "the relay survived every attach/detach cycle"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ws_tee_profile_flag_attaches_at_answer_time() {
    // The declarative twin of attach_ws_tee: `profile.ws_tee` on the answer stands the tee up in
    // one round-trip, and the call is teed the moment it is answered.
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
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let (uri, frames) = tee_server().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "tee-profile".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "tee-profile".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: ProfileFlags {
                    ws_tee: Some(uri),
                    ws_tee_direction: Some(WsTeeDirection::Caller),
                    ..Default::default()
                },
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("the answer still returns SDP")
        .remote_rtp;
    let start = expect_tee_start(&frames).await;
    assert_eq!(start.call_id, "tee-profile");
    assert_eq!(start.media.channels, 1);

    for sequence in 0..6u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    assert_eq!(next_tee_audio(&frames).await.len(), 320);

    // Deleting the call closes the tee.
    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "tee-profile".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    assert_eq!(
        engine.ws_tee_count(),
        0,
        "delete tore the tee down with the call"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tee_at_a_requested_wire_rate_upsamples_an_8k_call() {
    // The selectable wire rate: an 8 kHz G.711 call teed at 16 kHz must stream 16 kHz frames, and
    // both the `start` envelope and the `ws_tee_started` event must report the rate the consumer
    // actually receives — not the codec rate the leg happens to run at.
    let (engine, (phone_a, near_addr), _phone_b) = two_party_relay("tee-16k").await;
    let (uri, frames) = tee_server().await;

    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "tee-16k".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: Some(16_000),
            },
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");

    let start = expect_tee_start(&frames).await;
    assert_eq!(
        start.media.sample_rate, 16_000,
        "the start envelope announces the negotiated wire rate, not the 8 kHz codec rate"
    );
    assert_eq!(start.media.channels, 1);

    for sequence in 0..8u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    assert_eq!(
        next_tee_audio(&frames).await.len(),
        640,
        "16 kHz × 20 ms mono L16 = 320 samples = 640 bytes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stereo_tee_at_a_requested_wire_rate_frames_both_upsampled_legs() {
    // Both 8 kHz legs upsampled into one 16 kHz interleaved wire frame: 2 × 320 samples × 2 bytes.
    let (engine, (phone_a, near_addr), (phone_b, far_addr)) =
        two_party_relay("tee-16k-stereo").await;
    let (uri, frames) = tee_server().await;

    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "tee-16k-stereo".into(),
                from_tag: "tag-a".into(),
                ws_uri: uri,
                direction: WsTeeDirection::Both,
                channels: None,
                sample_rate: Some(16_000),
            },
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");

    let start = expect_tee_start(&frames).await;
    assert_eq!(start.media.sample_rate, 16_000);
    assert_eq!(start.media.channels, 2, "both legs ⇒ stereo");

    for sequence in 0..8u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
        phone_b
            .send_to(&g711_rtp(0, sequence, 0x0B0B_0B0B, 0x7F), far_addr)
            .await
            .expect("b send");
    }
    assert_eq!(
        next_tee_audio(&frames).await.len(),
        1280,
        "2 channels × 320 samples × 2 bytes at the negotiated 16 kHz"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unserviceable_tee_wire_rate_is_rejected_and_the_call_keeps_relaying() {
    // A rate the engine cannot frame must be a clean typed rejection at attach time — never a
    // silent clamp, never a half-attached tee, and never a disturbance to the relay underneath.
    let (engine, (phone_a, near_addr), (phone_b, _far)) = two_party_relay("tee-bad-rate").await;
    let (uri, _frames) = tee_server().await;

    for (rate, expected) in [
        (0u32, "must not be zero"),
        (44_100, "whole number of samples per millisecond"),
        (96_000, "outside the supported"),
    ] {
        let rejected = engine
            .handle(
                CLIENT,
                Command::AttachWsTee {
                    call_id: "tee-bad-rate".into(),
                    from_tag: "tag-a".into(),
                    ws_uri: uri.clone(),
                    direction: WsTeeDirection::Caller,
                    channels: None,
                    sample_rate: Some(rate),
                },
            )
            .await;
        match rejected {
            CmdResult::Error { reason } => assert!(
                reason.contains(expected),
                "{rate} Hz must be rejected with its own reason, got: {reason}"
            ),
            other => panic!("{rate} Hz must be rejected, got {other:?}"),
        }
        assert_eq!(engine.ws_tee_count(), 0, "{rate} Hz left a tee attached");
        assert!(
            !engine.media().is_media_call("tee-bad-rate"),
            "{rate} Hz promoted the relay it then failed to tee"
        );
    }

    // …and the relay is exactly as it was.
    phone_a
        .send_to(&g711_rtp(0, 100, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let (relayed, _) = recv(&phone_b).await;
    assert!(!relayed.is_empty(), "the call keeps relaying untouched");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_ws_tee_sample_rate_profile_flag_is_honoured_at_answer_time() {
    // The declarative twin: `ws_tee_sample_rate` alongside `ws_tee` on the answer.
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
    let (phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let (uri, frames) = tee_server().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "tee-profile-rate".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "tee-profile-rate".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: ProfileFlags {
                    ws_tee: Some(uri),
                    ws_tee_direction: Some(WsTeeDirection::Caller),
                    ws_tee_sample_rate: Some(16_000),
                    ..Default::default()
                },
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("the answer still returns SDP")
        .remote_rtp;

    let start = expect_tee_start(&frames).await;
    assert_eq!(start.media.sample_rate, 16_000);

    for sequence in 0..8u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    assert_eq!(next_tee_audio(&frames).await.len(), 640);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unserviceable_tee_wire_rate_in_the_profile_fails_the_answer() {
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
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    let (uri, _frames) = tee_server().await;

    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "tee-profile-bad".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "tee-profile-bad".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 0, "PCMU"),
                profile: ProfileFlags {
                    ws_tee: Some(uri),
                    ws_tee_sample_rate: Some(44_100),
                    ..Default::default()
                },
            },
        )
        .await;
    match answer {
        CmdResult::Error { reason } => assert!(
            reason.contains("whole number of samples per millisecond"),
            "the answer must carry the rate's own reason, got: {reason}"
        ),
        other => panic!("an unserviceable tee rate must fail the answer, got {other:?}"),
    }
    assert_eq!(engine.ws_tee_count(), 0, "no tee attached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ws_takeover_bridge_streams_at_the_requested_wire_rate_in_both_directions() {
    // The takeover half: an 8 kHz G.711 leg with `ws_sample_rate: 16000` must announce 16 kHz,
    // send 16 kHz uplink frames, AND render a 16 kHz downlink frame back into the call as one
    // 20 ms µ-law packet — the downlink conversion that did not exist before.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use futures_util::{SinkExt, StreamExt};
    use siphon_rtp_media::bridge::pcm_to_l16_le;
    use siphon_rtp_media::bridge::protocol::ControlMessage;
    use tokio_tungstenite::tungstenite::Message;

    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let ws_addr = ws_listener.local_addr().expect("ws addr");
    let (ws_tx, ws_rx) = flume::unbounded::<Message>();
    let (down_tx, down_rx) = flume::unbounded::<Vec<u8>>();
    tokio::spawn(async move {
        let (stream, _) = ws_listener.accept().await.expect("accept ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("ws handshake");
        let (mut sink, mut source) = socket.split();
        loop {
            tokio::select! {
                incoming = source.next() => match incoming {
                    Some(Ok(message)) => {
                        if ws_tx.send(message).is_err() {
                            break;
                        }
                    }
                    _ => break,
                },
                downlink = down_rx.recv_async() => match downlink {
                    Ok(bytes) => {
                        if sink.send(Message::binary(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
    });

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-16k".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(format!("ws://{ws_addr}/stream")),
                    ws_sample_rate: Some(16_000),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "{offer:?}");
    // The offer reply is the *far*-facing endpoint; the answer returns A's own, which is the one
    // the bridge redirected and the one phone A must send to.
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ws-16k".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;

    // 1. `start` announces the negotiated wire rate, not the leg's 8 kHz codec rate.
    let first = timeout(Duration::from_secs(3), ws_rx.recv_async())
        .await
        .expect("no timeout")
        .expect("a frame");
    match first {
        Message::Text(text) => match ControlMessage::from_json(text.as_str()) {
            Ok(ControlMessage::Start(data)) => assert_eq!(
                data.media.sample_rate, 16_000,
                "the start envelope is authoritative for the wire rate"
            ),
            other => panic!("expected start, got {other:?}"),
        },
        other => panic!("expected a start text frame, got {other:?}"),
    }

    // 2. Uplink: an 8 kHz µ-law packet surfaces as a 16 kHz L16 frame (640 bytes).
    for sequence in 0..6u16 {
        phone_a
            .send_to(&ulaw_rtp_packet(sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    let mut uplink_bytes = 0;
    for _ in 0..30 {
        let frame = timeout(Duration::from_secs(2), ws_rx.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        if let Message::Binary(bytes) = frame {
            uplink_bytes = bytes.len();
            break;
        }
    }
    assert_eq!(
        uplink_bytes, 640,
        "16 kHz × 20 ms mono L16 uplink = 320 samples = 640 bytes"
    );

    // 3. Downlink: a 16 kHz wire frame renders back into the call as ONE 20 ms µ-law packet.
    //    Without the wire→leg conversion the encoder would be handed 320 samples for an 8 kHz
    //    frame and the call would hear double speed.
    let mut l16 = vec![0u8; 640];
    pcm_to_l16_le(&[2000i16; 320], &mut l16);
    for _ in 0..4 {
        down_tx.send(l16.clone()).expect("queue downlink");
    }
    let mut rendered = None;
    for _ in 0..40 {
        let mut buffer = [0u8; 2048];
        if let Ok(Ok((len, _))) =
            timeout(Duration::from_millis(200), phone_a.recv_from(&mut buffer)).await
        {
            let packet =
                siphon_rtp_media::rtp::RtpPacket::parse(&buffer[..len]).expect("parse rtp");
            rendered = Some((packet.payload_type, packet.payload.len()));
            break;
        }
    }
    assert_eq!(
        rendered,
        Some((0, 160)),
        "one 20 ms µ-law frame at the leg's own 8 kHz rate"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ws_takeover_leg_reaches_the_turn_endpoint_within_the_configured_hangover() {
    // Regression, driven end to end through the control plane. `WsVadConfig::build_detector`
    // converts the trailing hangover from milliseconds into ptime frames, and the
    // detector-selection refactor called it with a hard-coded 1 ms ptime. `ws_vad_hangover_ms:
    // 300` therefore built an energy gate that held speech for 300 *frames* — six seconds at
    // this leg's 20 ms ptime — so `speech_stopped`, the turn endpoint a voice-AI server commits
    // ASR on, never arrived inside a normal turn. `speech_started` and barge-in kept working,
    // which is what disguised it, and the debug log one statement away printed the correct
    // frame count while the detector held 300.
    //
    // The conversion helper itself was never wrong, so calling `build_detector` directly with a
    // literal ptime cannot see this — only the engine's own call site can. This test never
    // names the helper: it offers a leg with `ws_vad`, lets the engine pick the codec, the
    // ptime and the detector, and asserts on what the WS server observes.
    //
    // The measurement is a **logical frame clock, not wall time**: the bridge stages at most one
    // uplink frame per ptime tick and emits exactly one binary WS frame per staged frame, and an
    // empty jitter buffer starves rather than conceals (`JitterBuffer::pop`), so one binary
    // frame is one frame the detector classified. Counting binary frames between the
    // `speech_started` and `speech_stopped` text frames measures the hangover in frames however
    // fast or slow the box is. The timeouts below are liveness nets, never the measurement.
    use crate::srtp_bridge::run_redirect_dispatcher;
    use futures_util::StreamExt;
    use siphon_rtp_media::bridge::protocol::ControlMessage;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio_tungstenite::tungstenite::Message;

    /// The hangover the controller asks for. At the leg's 20 ms ptime that is 15 frames.
    const HANGOVER_MS: u32 = 300;
    /// The turn endpoint must land within this many uplink frames of `speech_started`. Measured
    /// at 17-18 on this harness: the 15 hangover frames, plus the one or two already-queued loud
    /// frames that still drain after the talker falls silent. The *worst case* is bounded rather
    /// than hoped for — a stalled talker task makes `tokio::time::interval` burst its missed
    /// ticks, but the jitter buffer caps at 16 packets and drops the excess (it advances the
    /// cursor, so no concealment is manufactured either), so no more than 16 loud frames can
    /// still be in flight when the talker goes quiet: 16 + 15 = 31 is the ceiling even on a
    /// wedged box. 40 clears that and is still 7.5x under the 300 frames a millisecond-counted
    /// hangover produces.
    const MAX_FRAMES_TO_ENDPOINT: usize = 40;
    /// Below this the hangover would be too *short* to be the 300 ms that was asked for — a leg
    /// whose ptime was misread as 40 ms, say, would endpoint at around 7 frames. The floor is 15
    /// (silence cannot reach the detector before the edge that reports it), so this has the same
    /// kind of margin underneath as the ceiling has above.
    const MIN_FRAMES_TO_ENDPOINT: usize = 10;
    /// Stop reading rather than hang if the bridge goes quiet without reaching either edge.
    const MAX_FRAMES_READ: usize = 2_000;

    // A WS server that forwards everything it receives. This test asserts on the engine's
    // uplink and turn signals, so it never plays anything back into the call.
    let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let ws_addr = ws_listener.local_addr().expect("ws addr");
    let (ws_tx, ws_rx) = flume::unbounded::<Message>();
    let server = tokio::spawn(async move {
        let (stream, _) = ws_listener.accept().await.expect("accept ws");
        let socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("ws handshake");
        let (_sink, mut source) = socket.split();
        while let Some(Ok(message)) = source.next().await {
            if ws_tx.send(message).is_err() {
                break;
            }
        }
    });

    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-vad-hangover".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(format!("ws://{ws_addr}/stream")),
                    ws_vad: true,
                    ws_vad_hangover_ms: Some(HANGOVER_MS),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(matches!(offer, CmdResult::Ok { .. }), "{offer:?}");
    // The answer returns A's own endpoint — the one the bridge redirected, and the one phone A
    // has to send to for its media to reach the WS leg.
    let answer = engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ws-vad-hangover".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags::default(),
            },
        )
        .await;
    let near_addr = sdp::parse(&ok_sdp_text(&answer))
        .expect("answer reply")
        .remote_rtp;

    // The talker: 20 ms µ-law frames, loud until this test has seen `speech_started`, silent
    // from then on. Paced at the leg's own ptime so the shallow jitter buffer (target 1, cap 16)
    // neither backs up nor is ever asked to conceal, which is what keeps one sent packet equal
    // to one classified frame. Loud is the same 4000-amplitude frame the bridge core's own VAD
    // tests use — mean-square energy 16e6, well over the 1e6 default threshold — and silence
    // encodes to zero, which is under it.
    let loud = ulaw_byte(4_000);
    let silence = ulaw_byte(0);
    let talker_silent = Arc::new(AtomicBool::new(false));
    let sender_silent = Arc::clone(&talker_silent);
    let talker = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(20));
        for sequence in 0..1_000u16 {
            ticker.tick().await;
            let payload_byte = if sender_silent.load(Ordering::Relaxed) {
                silence
            } else {
                loud
            };
            if phone_a
                .send_to(
                    &ulaw_rtp_packet(sequence, 0x0A0A_0A0A, payload_byte),
                    near_addr,
                )
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let mut started = false;
    let mut frames_since_start = 0usize;
    let mut frames_to_endpoint = None;
    for _ in 0..MAX_FRAMES_READ {
        let message = timeout(Duration::from_secs(5), ws_rx.recv_async())
            .await
            .expect("the bridge kept the socket busy")
            .expect("the ws server stayed up");
        match message {
            Message::Text(text) => match ControlMessage::from_json(text.as_str()) {
                Ok(ControlMessage::SpeechStarted(_)) => {
                    started = true;
                    talker_silent.store(true, Ordering::Relaxed);
                }
                Ok(ControlMessage::SpeechStopped(_)) => {
                    frames_to_endpoint = Some(frames_since_start);
                    break;
                }
                _ => {}
            },
            // One binary frame is one 20 ms frame the detector classified. Frames before the
            // speech edge are the talker warming up and are not part of the hangover.
            Message::Binary(_) if started => {
                frames_since_start += 1;
                if frames_since_start > MAX_FRAMES_TO_ENDPOINT {
                    break;
                }
            }
            _ => {}
        }
    }
    talker.abort();
    server.abort();

    assert!(
        started,
        "the loud uplink never produced a speech_started edge"
    );
    let Some(frames_to_endpoint) = frames_to_endpoint else {
        panic!(
            "no speech_stopped after {frames_since_start} uplink frames: a {HANGOVER_MS} ms \
                 hangover at this leg's 20 ms ptime is 15 frames, so the turn endpoint must land \
                 inside {MAX_FRAMES_TO_ENDPOINT} — a hangover counted in milliseconds instead of \
                 ptime frames holds speech for {HANGOVER_MS} frames (six seconds) and the server \
                 never gets to commit the turn"
        );
    };
    assert!(
        (MIN_FRAMES_TO_ENDPOINT..=MAX_FRAMES_TO_ENDPOINT).contains(&frames_to_endpoint),
        "the turn endpoint landed {frames_to_endpoint} uplink frames after speech_started; a \
             {HANGOVER_MS} ms hangover at a 20 ms ptime is 15 frames, so it belongs in \
             {MIN_FRAMES_TO_ENDPOINT}..={MAX_FRAMES_TO_ENDPOINT}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unserviceable_ws_bridge_wire_rate_fails_the_offer_without_a_half_built_call() {
    // The rate is validated before the redirect is installed and before the server is dialled, so
    // a bad one leaves no WS route, no promoted call and no socket — it is simply refused.
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
    let (_phone_a, addr_a) = phone().await;

    // A deliberately dead address: the dial would fail too, so a rejection that mentions the
    // *rate* proves validation ran first, before anything was installed or dialled.
    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-bad-rate".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some("ws://192.0.2.1:9/stream".to_string()),
                    ws_sample_rate: Some(44_100),
                    ..Default::default()
                },
            },
        )
        .await;
    match offer {
        CmdResult::Error { reason } => assert!(
            reason.contains("whole number of samples per millisecond"),
            "the rate must be rejected before the dial, got: {reason}"
        ),
        other => panic!("an unserviceable wire rate must fail the offer, got {other:?}"),
    }
    assert!(
        !engine.ws().is_ws_call("ws-bad-rate"),
        "no WS route left behind"
    );
}

/// The echo canceller's search window is validated at the control plane, on the verbs that carry
/// a profile, before a port is allocated or a dialog is committed. It is one of the few knobs
/// whose wrong value is *invisible at runtime* — a window that is too short leaves the canceller
/// running and cancelling nothing — so an out-of-range request is refused where the controller
/// can still see it rather than absorbed.
#[tokio::test]
async fn an_out_of_range_echo_delay_search_window_fails_the_offer() {
    let engine = Engine::new(UdpLoopbackDatapath::new());
    let (_phone_a, addr_a) = phone().await;

    let offer = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "aec-bad-window".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    echo_cancellation: true,
                    echo_delay_search_ms: Some(5_000),
                    ..Default::default()
                },
            },
        )
        .await;
    match offer {
        CmdResult::Error { reason } => {
            assert!(
                reason.contains("echo-delay-search-range"),
                "the refusal must be greppable, got: {reason}"
            );
            assert!(
                reason.contains("5000"),
                "the refusal must name the offending value, got: {reason}"
            );
        }
        other => {
            panic!("an out-of-range echo search window must fail the offer, got {other:?}")
        }
    }

    // A value inside the bounds is accepted on the same path, so the check is a range test and
    // not a blanket refusal of the field.
    let good = engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "aec-good-window".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    echo_cancellation: true,
                    echo_delay_search_ms: Some(512),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(
        matches!(good, CmdResult::Ok { .. }),
        "a serviceable window must be accepted, got {good:?}"
    );
}

// ---- WebSocket takeover-bridge lifecycle (attach / re-point / detach) ------------------------
//
// Until these, a takeover bridge was created at negotiation and destroyed with the call: there
// was no way to put one on a call already up, move one, or take one off. These cover the three,
// and the refusals that keep a detach from ever answering `ok` on a call with no audio path.

/// A WS server that completes the handshake and immediately closes — the "the consumer went
/// away mid-call" shape, which used to be entirely silent.
async fn closing_ws_server() -> String {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let addr = listener.local_addr().expect("ws addr");
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept ws");
        let mut socket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("ws handshake");
        // RFC 6455 §5.5.1: an orderly close, which is what a consumer shutting down sends. A
        // bare TCP reset would be a `TransportError` instead — a different reason, on purpose.
        let _ = socket.send(Message::Close(None)).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    });
    format!("ws://{addr}/stream")
}

/// A WS server that accepts connection after connection and closes each one the moment the
/// handshake completes — the repeated form of [`closing_ws_server`], for a guard that needs many
/// attempts rather than one.
async fn closing_ws_server_repeating() -> String {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ws");
    let addr = listener.local_addr().expect("ws addr");
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await {
                    let _ = socket.send(Message::Close(None)).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            });
        }
    });
    format!("ws://{addr}/tee")
}

/// Drain a takeover server's frames until the `start` handshake, returning what it announced.
async fn expect_bridge_start(
    frames: &flume::Receiver<tokio_tungstenite::tungstenite::Message>,
) -> siphon_rtp_media::bridge::protocol::StartData {
    use siphon_rtp_media::bridge::protocol::ControlMessage;
    use tokio_tungstenite::tungstenite::Message;
    for _ in 0..8 {
        let message = timeout(Duration::from_secs(3), frames.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        if let Message::Text(text) = message {
            if let Ok(ControlMessage::Start(data)) = ControlMessage::from_json(text.as_str()) {
                return data;
            }
        }
    }
    panic!("no start frame arrived");
}

/// Drain the takeover server until a binary (uplink audio) frame arrives.
async fn expect_bridge_uplink(
    frames: &flume::Receiver<tokio_tungstenite::tungstenite::Message>,
) -> Vec<u8> {
    use tokio_tungstenite::tungstenite::Message;
    for _ in 0..40 {
        let message = timeout(Duration::from_secs(3), frames.recv_async())
            .await
            .expect("no timeout")
            .expect("a frame");
        if let Message::Binary(bytes) = message {
            return bytes.to_vec();
        }
    }
    panic!("no uplink audio frame arrived");
}

/// Drain `events` until the next WS-**tee** lifecycle event, or `None` if none arrives.
///
/// Deliberately narrow: it skips only events of other *kinds*, never a tee event it did not
/// want. A helper that drained until it found the tee event the caller was hoping for could not
/// see an ordering defect at all — which is precisely how the tee's start/end ordering bug
/// survived from the day it shipped until the takeover bridge inherited the same shape.
async fn next_ws_tee_event(events: &flume::Receiver<Event>) -> Option<Event> {
    for _ in 0..64 {
        let event = timeout(Duration::from_secs(3), events.recv_async())
            .await
            .ok()?
            .ok()?;
        if matches!(event, Event::WsTeeStarted { .. } | Event::WsTeeEnded { .. }) {
            return Some(event);
        }
    }
    None
}

/// Drain `events` until the next WS-bridge lifecycle event, or `None` if none arrives.
async fn next_ws_bridge_event(events: &flume::Receiver<Event>) -> Option<Event> {
    for _ in 0..64 {
        let event = timeout(Duration::from_secs(3), events.recv_async())
            .await
            .ok()?
            .ok()?;
        if matches!(
            event,
            Event::WsBridgeStarted { .. } | Event::WsBridgeEnded { .. }
        ) {
            return Some(event);
        }
    }
    None
}

/// Whether `socket` receives anything within `millis` — a non-panicking `recv`.
async fn receives_within(socket: &UdpSocket, millis: u64) -> bool {
    let mut buffer = [0u8; 2048];
    timeout(Duration::from_millis(millis), socket.recv_from(&mut buffer))
        .await
        .is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attaching_a_ws_bridge_takes_a_live_relay_over_and_detaching_gives_it_back() {
    // The headline round trip. A plain two-party G.711 relay is carrying audio; a takeover is
    // attached to it at runtime (no re-INVITE, the leg's ports and gate do not move); leg A's
    // audio now goes to the WS server and leg B hears nothing, which is what a takeover *is*;
    // and a detach reinstalls the exact `Forward` rules that were displaced, so the two parties
    // go back to hearing each other.
    let (engine, (phone_a, near_addr), (phone_b, far_addr)) = two_party_relay("ws-attach").await;
    let events = engine.register_client(CLIENT);

    // The relay works before anything is attached — otherwise the "B hears nothing" assertion
    // below would pass for the wrong reason.
    phone_a
        .send_to(&g711_rtp(0, 0, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let (relayed, _) = recv(&phone_b).await;
    assert!(!relayed.is_empty(), "the relay carries audio before attach");

    let (ws_uri, frames, _downlink) = takeover_ws_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "ws-attach".into(),
                from_tag: "tag-a".into(),
                ws_uri: ws_uri.clone(),
            },
        )
        .await;
    assert!(
        matches!(attached, CmdResult::Ok { .. }),
        "attach: {attached:?}"
    );
    assert!(engine.ws().is_ws_call("ws-attach"), "the bridge is up");
    assert_eq!(
        engine
            .calls
            .get("ws-attach")
            .expect("call present")
            .pipeline,
        PipelineKind::Ws,
    );

    match next_ws_bridge_event(&events).await {
        Some(Event::WsBridgeStarted {
            stream_id,
            ws_uri: reported,
            sample_rate,
            ..
        }) => {
            assert_eq!(
                stream_id, "ws-ws-attach",
                "the WS start frame's own stream id"
            );
            assert_eq!(reported, ws_uri);
            assert_eq!(sample_rate, 8000, "the G.711 leg's own PCM rate");
        }
        other => panic!("expected ws_bridge_started, got {other:?}"),
    }

    let start = expect_bridge_start(&frames).await;
    assert_eq!(start.media.sample_rate, 8000);
    assert_eq!(start.media.channels, 1, "a takeover leg is one mono leg");

    // A talks: the WS server hears it, and B does not — the relay is unwired.
    for sequence in 1..10u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    assert_eq!(
        expect_bridge_uplink(&frames).await.len(),
        320,
        "8 kHz x 20 ms mono L16 = 160 samples = 320 bytes"
    );
    assert!(
        !receives_within(&phone_b, 300).await,
        "a takeover unwires A<->B: B must not receive A's media while the bridge holds the leg"
    );

    // Detach puts the relay back, verbatim.
    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsBridge {
                call_id: "ws-attach".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "detach: {detached:?}"
    );
    assert!(
        !engine.ws().is_ws_call("ws-attach"),
        "the bridge is gone after detach"
    );
    assert_eq!(
        engine
            .calls
            .get("ws-attach")
            .expect("call present")
            .pipeline,
        PipelineKind::Passthrough,
        "the call is a plain relay again"
    );
    match next_ws_bridge_event(&events).await {
        Some(Event::WsBridgeEnded { reason, .. }) => {
            assert_eq!(reason, WsBridgeEndReason::Detached);
        }
        other => panic!("expected ws_bridge_ended, got {other:?}"),
    }

    // Both directions relay again.
    phone_a
        .send_to(&g711_rtp(0, 50, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let (to_b, _) = recv(&phone_b).await;
    assert!(!to_b.is_empty(), "A reaches B again after detach");
    phone_b
        .send_to(&g711_rtp(0, 50, 0x0B0B_0B0B, 0xFF), far_addr)
        .await
        .expect("b send");
    let (to_a, _) = recv(&phone_a).await;
    assert!(!to_a.is_empty(), "B reaches A again after detach");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn re_pointing_a_ws_bridge_moves_a_live_call_to_a_second_consumer() {
    // The blocker this work package exists for: moving a live call's audio to a different
    // consumer. The leg is untouched — same ports, same codec, same gate — so there is no
    // re-INVITE and the caller never hears the handover as anything but a gap.
    use crate::srtp_bridge::run_redirect_dispatcher;

    let (first_uri, first_frames, _first_down) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let events = engine.register_client(CLIENT);
    let (phone_a, addr_a) = phone().await;

    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ws-move".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(first_uri.clone()),
                    ws_sample_rate: Some(16_000),
                    ..Default::default()
                },
            },
        )
        .await;
    let caller_target = sdp::parse(&ok_sdp_text(&answered))
        .expect("answer sdp")
        .remote_rtp;
    assert_eq!(
        expect_bridge_start(&first_frames).await.media.sample_rate,
        16_000
    );
    match next_ws_bridge_event(&events).await {
        Some(Event::WsBridgeStarted {
            ws_uri: reported, ..
        }) => assert_eq!(reported, first_uri),
        other => panic!("expected ws_bridge_started, got {other:?}"),
    }

    // Move it.
    let (second_uri, second_frames, _second_down) = takeover_ws_server().await;
    let moved = engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "ws-move".into(),
                from_tag: "tag-a".into(),
                ws_uri: second_uri.clone(),
            },
        )
        .await;
    assert!(matches!(moved, CmdResult::Ok { .. }), "re-point: {moved:?}");
    assert!(engine.ws().is_ws_call("ws-move"), "still bridged");

    // Exactly one orderly end and one start, in that order.
    match next_ws_bridge_event(&events).await {
        Some(Event::WsBridgeEnded { reason, .. }) => {
            assert_eq!(
                reason,
                WsBridgeEndReason::Detached,
                "a re-point ends the old connection as an orderly detach"
            );
        }
        other => panic!("expected ws_bridge_ended, got {other:?}"),
    }
    match next_ws_bridge_event(&events).await {
        Some(Event::WsBridgeStarted {
            ws_uri: reported,
            sample_rate,
            stream_id,
            ..
        }) => {
            assert_eq!(reported, second_uri, "the new consumer");
            assert_eq!(
                sample_rate, 16_000,
                "a re-point carries the negotiated wire rate across; a controller moving the \
                     destination did not ask for its 16 kHz wire to silently drop to the leg rate"
            );
            assert_eq!(
                stream_id, "ws-ws-move",
                "the correlator is the call's, not the connection's"
            );
        }
        other => panic!("expected ws_bridge_started, got {other:?}"),
    }

    // The second server gets the handshake at the carried-over rate, and the caller's audio.
    assert_eq!(
        expect_bridge_start(&second_frames).await.media.sample_rate,
        16_000
    );
    for sequence in 0..12u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), caller_target)
            .await
            .expect("a send");
    }
    assert_eq!(
        expect_bridge_uplink(&second_frames).await.len(),
        640,
        "16 kHz x 20 ms mono L16 = 320 samples = 640 bytes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detaching_a_negotiated_ws_bridge_is_refused_rather_than_muting_the_call() {
    // The decision this verb turns on. A bridge negotiated with `ws_uri` *is* the call's media
    // path — on `answer_local` there is not even a second party — so there is nothing to hand
    // the call back to. Refuse and say so, rather than answer `ok` on a call that now has no
    // audio path at all, which is the exact failure the lifecycle work is meant to prevent.
    use crate::srtp_bridge::run_redirect_dispatcher;

    let (ws_uri, frames, _down) = takeover_ws_server().await;
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (phone_a, addr_a) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ws-negotiated".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(ws_uri),
                    ..Default::default()
                },
            },
        )
        .await;
    let caller_target = sdp::parse(&ok_sdp_text(&answered))
        .expect("answer sdp")
        .remote_rtp;
    let _ = expect_bridge_start(&frames).await;

    let refused = engine
        .handle(
            CLIENT,
            Command::DetachWsBridge {
                call_id: "ws-negotiated".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    match refused {
        CmdResult::Error { reason } => assert!(
            reason.contains("ws-bridge-negotiated"),
            "the refusal must name the reason, got: {reason}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }

    // And the refusal left the call exactly as it was — still bridged, still carrying audio.
    assert!(engine.ws().is_ws_call("ws-negotiated"));
    for sequence in 0..12u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), caller_target)
            .await
            .expect("a send");
    }
    assert_eq!(expect_bridge_uplink(&frames).await.len(), 320);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detaching_a_call_with_no_ws_bridge_is_a_no_op() {
    // Idempotent, like `detach_ws_tee`, so a controller can call it unconditionally on hangup.
    let (engine, (phone_a, near_addr), (phone_b, _far)) = two_party_relay("ws-nodetach").await;
    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsBridge {
                call_id: "ws-nodetach".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(matches!(detached, CmdResult::Ok { .. }), "{detached:?}");
    phone_a
        .send_to(&g711_rtp(0, 0, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let (relayed, _) = recv(&phone_b).await;
    assert!(
        !relayed.is_empty(),
        "the relay is untouched by a no-op detach"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attaching_a_ws_bridge_is_refused_where_the_media_path_could_not_be_given_back() {
    // Every refusal names its own token, because each is a different thing for a controller to
    // do about it. The common thread: a takeover is only offered where a detach can restore
    // exactly what it displaced.
    use crate::srtp_bridge::run_redirect_dispatcher;

    // 1. A transcoding call — its actor is built from the negotiation, not reconstructible here.
    let engine = Engine::new(UdpLoopbackDatapath::new());
    tokio::spawn(run_redirect_dispatcher(
        engine.datapath().rx(),
        engine.bridge(),
        engine.media(),
        engine.ws(),
        engine.conference(),
        None,
    ));
    let (_phone_a, addr_a) = phone().await;
    let (_phone_b, addr_b) = phone().await;
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-transcode".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_single_codec(addr_a, 0, "PCMU"),
                profile: Default::default(),
            },
        )
        .await;
    engine
        .handle(
            CLIENT,
            Command::Answer {
                call_id: "ws-transcode".into(),
                from_tag: "tag-a".into(),
                to_tag: "tag-b".into(),
                sdp: sdp_single_codec(addr_b, 8, "PCMA"),
                profile: Default::default(),
            },
        )
        .await;
    let (ws_uri, _frames, _down) = takeover_ws_server().await;
    match engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "ws-transcode".into(),
                from_tag: "tag-a".into(),
                ws_uri: ws_uri.clone(),
            },
        )
        .await
    {
        CmdResult::Error { reason } => assert!(
            reason.contains("ws-takeover-not-a-plain-relay"),
            "got: {reason}"
        ),
        other => panic!("a transcoding call must be refused, got {other:?}"),
    }
    assert!(!engine.ws().is_ws_call("ws-transcode"), "nothing attached");

    // 2. An unanswered offer — there is no second party a detach could hand it back to.
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-unanswered".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: Default::default(),
            },
        )
        .await;
    match engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "ws-unanswered".into(),
                from_tag: "tag-a".into(),
                ws_uri: ws_uri.clone(),
            },
        )
        .await
    {
        CmdResult::Error { reason } => {
            assert!(reason.contains("ws-takeover-not-answered"), "got: {reason}");
        }
        other => panic!("an unanswered call must be refused, got {other:?}"),
    }

    // 3. A secure offerer — the engine is not that leg's cryptographic far side on a two-leg
    //    call, so the bridge would be handed ciphertext and would answer in the clear. Same
    //    reason token `offer` and `answer` already use.
    let peer_key =
        CryptoAttribute::generate(1, CryptoSuite::AesCm128HmacSha1_80).expect("peer key");
    engine
        .handle(
            CLIENT,
            Command::Offer {
                call_id: "ws-secure".into(),
                from_tag: "tag-a".into(),
                sdp: sdes_offerer_sdp(addr_a, &peer_key),
                profile: Default::default(),
            },
        )
        .await;
    match engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "ws-secure".into(),
                from_tag: "tag-a".into(),
                ws_uri,
            },
        )
        .await
    {
        CmdResult::Error { reason } => assert!(
            reason.contains("ws-takeover-secure-offerer"),
            "the runtime attach must make the same refusal the negotiation path does, got: \
                 {reason}"
        ),
        other => panic!("a secure offerer must be refused, got {other:?}"),
    }
    assert!(!engine.ws().is_ws_call("ws-secure"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attaching_a_ws_bridge_is_refused_while_a_tee_holds_the_call() {
    // A tee taps the post-decode fan-out of the very media path a takeover removes. Refusing is
    // the same posture `attach_ws_tee` already takes in the other direction (a takeover call
    // cannot be teed) — neither side silently turns the other off.
    let (engine, _a, _b) = two_party_relay("ws-vs-tee").await;
    let (tee_uri, _tee_frames) = tee_server().await;
    let teed = engine
        .handle(
            CLIENT,
            Command::AttachWsTee {
                call_id: "ws-vs-tee".into(),
                from_tag: "tag-a".into(),
                ws_uri: tee_uri,
                direction: WsTeeDirection::Caller,
                channels: None,
                sample_rate: None,
            },
        )
        .await;
    assert!(matches!(teed, CmdResult::Ok { .. }), "{teed:?}");

    let (ws_uri, _frames, _down) = takeover_ws_server().await;
    match engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "ws-vs-tee".into(),
                from_tag: "tag-a".into(),
                ws_uri,
            },
        )
        .await
    {
        CmdResult::Error { reason } => {
            assert!(reason.contains("ws-takeover-call-is-held"), "got: {reason}");
        }
        other => panic!("a teed call must be refused, got {other:?}"),
    }
    assert!(!engine.ws().is_ws_call("ws-vs-tee"), "nothing attached");
    assert_eq!(
        engine.ws_tee_count(),
        1,
        "the tee is untouched by the refusal"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ws_bridge_the_server_drops_reports_itself_in_order_instead_of_going_silent() {
    // Two guarantees at once, on the shape that stresses both: a server that closes on the
    // handshake, so the bridge ends within microseconds of starting.
    //
    // 1. It is *reported*. A takeover bridge is leg A's only far side, so a server that goes
    //    away leaves a live call one-way, and until `ws_bridge_ended` nothing anywhere said so.
    // 2. It is reported **after its own start**. This is the half that was wrong: the bridge
    //    task was spawned before the start event was enqueued, so under scheduling pressure the
    //    end overtook it and a consumer got an end for a stream it had never been told about —
    //    a fault or a leak for any controller keying per-stream state on the start. The start is
    //    now enqueued before the task exists, so the FIFO event channel orders the two.
    //
    // The assertions below are deliberately on the *sequence*, not on "an end arrives
    // eventually": a test that drains until it finds the event it wants cannot see this defect.
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
    let events = engine.register_client(CLIENT);
    let (_phone_a, addr_a) = phone().await;
    let answered = engine
        .handle(
            CLIENT,
            Command::AnswerLocal {
                call_id: "ws-dies".into(),
                from_tag: "tag-a".into(),
                sdp: sdp_for(addr_a, true),
                profile: ProfileFlags {
                    ws_uri: Some(closing_ws_server().await),
                    ..Default::default()
                },
            },
        )
        .await;
    assert!(matches!(answered, CmdResult::Ok { .. }), "{answered:?}");

    // FIRST, before anything else on this channel: the start.
    let started_stream = match next_ws_bridge_event(&events).await {
        Some(Event::WsBridgeStarted {
            call_id, stream_id, ..
        }) => {
            assert_eq!(call_id, "ws-dies");
            stream_id
        }
        other => panic!(
            "the start must be the first bridge event a consumer sees, even when the server \
                 ends the bridge immediately — got {other:?}"
        ),
    };
    // ...and only then the end, naming the same stream.
    match next_ws_bridge_event(&events).await {
        Some(Event::WsBridgeEnded {
            call_id,
            from_tag,
            stream_id,
            reason,
        }) => {
            assert_eq!(call_id, "ws-dies");
            assert_eq!(from_tag, "tag-a");
            assert_eq!(
                stream_id, started_stream,
                "the end names the stream the start announced"
            );
            assert_eq!(
                reason,
                WsBridgeEndReason::ServerClosed,
                "the controller learns which end gave up, not merely that audio stopped"
            );
        }
        other => panic!("expected ws_bridge_ended, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ws_tee_the_server_drops_reports_its_start_before_its_end() {
    // The tee's half of the ordering guarantee, and it needs its own guard for a reason: the tee
    // carried this defect from the day it shipped, and its existing test could never have caught
    // it — that test drains until it finds `ws_tee_started`, so an end that overtook the start is
    // skipped over on the way. This asserts the *sequence* instead.
    //
    // It is a **repeated** guard, not a single attempt, and that is deliberate. The window the
    // defect lives in is one map insert here (against a watch, a second spawn and two inserts on
    // the takeover bridge), so a single attach observes a reordering far too rarely to gate on:
    // reverting the fix and running the whole engine suite fifteen times caught it zero times,
    // where the bridge's single-shot guard caught its own reordering twice in fifteen. Many
    // rounds turn a rare window into one this will actually sit on. It can only ever fail when
    // the ordering is genuinely violated, so repetition costs nothing but coverage.
    let (engine, _phone_a, _phone_b) = two_party_relay("tee-order").await;
    let events = engine.register_client(CLIENT);
    let uri = closing_ws_server_repeating().await;

    for round in 0..512 {
        let attached = engine
            .handle(
                CLIENT,
                Command::AttachWsTee {
                    call_id: "tee-order".into(),
                    from_tag: "tag-a".into(),
                    ws_uri: uri.clone(),
                    direction: WsTeeDirection::Caller,
                    channels: None,
                    sample_rate: None,
                },
            )
            .await;
        assert!(
            matches!(attached, CmdResult::Ok { .. }),
            "round {round} attach: {attached:?}"
        );

        // FIRST, before anything else on this channel: the start.
        let started_stream = match next_ws_tee_event(&events).await {
            Some(Event::WsTeeStarted {
                call_id, stream_id, ..
            }) => {
                assert_eq!(call_id, "tee-order");
                stream_id
            }
            other => panic!(
                "round {round}: the start must be the first tee event a consumer sees, even \
                     when the server ends the stream immediately — got {other:?}"
            ),
        };
        // ...and only then the end, naming the stream the start announced.
        match next_ws_tee_event(&events).await {
            Some(Event::WsTeeEnded {
                call_id, stream_id, ..
            }) => {
                assert_eq!(call_id, "tee-order");
                assert_eq!(
                    stream_id, started_stream,
                    "round {round}: the end names the stream the start announced"
                );
            }
            other => panic!("round {round}: expected ws_tee_ended, got {other:?}"),
        }

        // Clear the tee so the next round attaches fresh rather than replacing. The end has
        // already been reported by the transport, so this emits nothing (the once-only latch).
        let detached = engine
            .handle(
                CLIENT,
                Command::DetachWsTee {
                    call_id: "tee-order".into(),
                    from_tag: "tag-a".into(),
                },
            )
            .await;
        assert!(
            matches!(detached, CmdResult::Ok { .. }),
            "round {round} detach: {detached:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_taken_over_call_can_be_detached_back_to_its_relay_after_the_server_dies() {
    // The recovery the end event exists to make possible. The engine deliberately does not
    // re-point or restore anything by itself when a consumer goes away — it holds the leg and
    // reports — so the controller's options have to still work afterwards. They do: the record
    // (and its restore plan) outlives the dead bridge task, so a detach still hands the call back
    // to the two parties it took it from.
    let (engine, (phone_a, near_addr), (phone_b, _far_addr)) = two_party_relay("ws-recover").await;
    let events = engine.register_client(CLIENT);

    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "ws-recover".into(),
                from_tag: "tag-a".into(),
                ws_uri: closing_ws_server().await,
            },
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    assert!(matches!(
        next_ws_bridge_event(&events).await,
        Some(Event::WsBridgeStarted { .. })
    ));
    match next_ws_bridge_event(&events).await {
        Some(Event::WsBridgeEnded { reason, .. }) => {
            assert_eq!(reason, WsBridgeEndReason::ServerClosed);
        }
        other => panic!("expected ws_bridge_ended, got {other:?}"),
    }

    let detached = engine
        .handle(
            CLIENT,
            Command::DetachWsBridge {
                call_id: "ws-recover".into(),
                from_tag: "tag-a".into(),
            },
        )
        .await;
    assert!(
        matches!(detached, CmdResult::Ok { .. }),
        "a dead bridge is still detachable: {detached:?}"
    );
    phone_a
        .send_to(&g711_rtp(0, 0, 0x0A0A_0A0A, 0xFF), near_addr)
        .await
        .expect("a send");
    let (to_b, _) = recv(&phone_b).await;
    assert!(!to_b.is_empty(), "the two parties have their relay back");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deleting_a_bridged_call_reports_the_bridge_ending_with_it() {
    let (engine, _a, _b) = two_party_relay("ws-delete").await;
    let events = engine.register_client(CLIENT);
    let (ws_uri, frames, _down) = takeover_ws_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "ws-delete".into(),
                from_tag: "tag-a".into(),
                ws_uri,
            },
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let _ = expect_bridge_start(&frames).await;
    assert!(matches!(
        next_ws_bridge_event(&events).await,
        Some(Event::WsBridgeStarted { .. })
    ));

    engine
        .handle(
            CLIENT,
            Command::Delete {
                call_id: "ws-delete".into(),
                from_tag: "tag-a".into(),
                to_tag: None,
            },
        )
        .await;
    match next_ws_bridge_event(&events).await {
        Some(Event::WsBridgeEnded { reason, .. }) => {
            assert_eq!(reason, WsBridgeEndReason::CallEnded);
        }
        other => panic!("expected ws_bridge_ended, got {other:?}"),
    }
    assert!(
        !engine.ws().is_ws_call("ws-delete"),
        "torn down with the call"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocking_a_taken_over_call_is_refused_rather_than_undoing_the_takeover() {
    // A taken-over call still carries the displaced relay's `Forward` rules so its detach can
    // reinstall them. `block_media` walks exactly that list, so an unblock would have quietly
    // pulled leg A back off the bridge. Refuse — the same posture recording, SIPREC and the tee
    // already take on a takeover call.
    let (engine, (phone_a, near_addr), _b) = two_party_relay("ws-block").await;
    let (ws_uri, frames, _down) = takeover_ws_server().await;
    let attached = engine
        .handle(
            CLIENT,
            Command::AttachWsBridge {
                call_id: "ws-block".into(),
                from_tag: "tag-a".into(),
                ws_uri,
            },
        )
        .await;
    assert!(matches!(attached, CmdResult::Ok { .. }), "{attached:?}");
    let _ = expect_bridge_start(&frames).await;

    for block in [true, false] {
        let result = engine
            .handle(
                CLIENT,
                if block {
                    Command::BlockMedia {
                        call_id: "ws-block".into(),
                        from_tag: "tag-a".into(),
                    }
                } else {
                    Command::UnblockMedia {
                        call_id: "ws-block".into(),
                        from_tag: "tag-a".into(),
                    }
                },
            )
            .await;
        assert!(
            matches!(result, CmdResult::Error { .. }),
            "block={block} must be refused on a takeover call, got {result:?}"
        );
    }

    // And the bridge still has the leg.
    for sequence in 0..12u16 {
        phone_a
            .send_to(&g711_rtp(0, sequence, 0x0A0A_0A0A, 0xFF), near_addr)
            .await
            .expect("a send");
    }
    assert_eq!(expect_bridge_uplink(&frames).await.len(), 320);
}
