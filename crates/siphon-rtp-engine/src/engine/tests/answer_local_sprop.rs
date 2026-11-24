//! The far party's out-of-band H.264 parameter sets on an `answer_local` + `offer_far` call (RFC 6184
//! §8.1). The caller's answer is frozen (RFC 3264 §8), so it never learns `sprop-parameter-sets`;
//! the engine hands them over in-band, ahead of the first IDR it relays, and then returns the stream
//! to the kernel fast path.

use super::answer_local_video::{delete, grown_edited, parse_picture_loss, Grown, CALL};
use super::call_video::received;
use super::*;
use crate::video_injector::{Tick, VideoInjector, SETTLE_PACKETS};
use siphon_rtp_datapath::{RxPacket, SourceFilter};

const SPS: [u8; 9] = [0x67, 0x42, 0xC0, 0x1E, 0xDA, 0x02, 0x80, 0xF6, 0x40];
const PPS: [u8; 4] = [0x68, 0xCE, 0x3C, 0x80];
/// `SPS` and `PPS` as an `a=fmtp` `sprop-parameter-sets` value (RFC 6184 §8.1).
const SPROP: &str = "Z0LAHtoCgPZA,aM48gA==";
const IN_BAND_SPS: [u8; 4] = [0x67, 0x4D, 0x00, 0x1F];
const IN_BAND_PPS: [u8; 4] = [0x68, 0xEB, 0xE3, 0xCB];
const IDR: [u8; 6] = [0x65, 0x88, 0x84, 0x00, 0x11, 0x22];
const P_SLICE: [u8; 4] = [0x41, 0x9A, 0x00, 0x33];
const FAR_SSRC: u32 = 0xFA12_0001;

/// One RTP packet of the far party's stream, payload type 96.
fn far_rtp(sequence: u16, timestamp: u32, marker: bool, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x80, if marker { 0x80 | 96 } else { 96 }];
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(&timestamp.to_be_bytes());
    packet.extend_from_slice(&FAR_SSRC.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// What the caller received: `(sequence, timestamp, ssrc, marker, payload type, payload)`.
fn fields(datagram: &[u8]) -> (u16, u32, u32, bool, u8, Vec<u8>) {
    (
        u16::from_be_bytes([datagram[2], datagram[3]]),
        u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]),
        u32::from_be_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]),
        datagram[1] & 0x80 != 0,
        datagram[1] & 0x7F,
        datagram[12..].to_vec(),
    )
}

/// A grown call whose far answer carries `sprop-parameter-sets` (when `sprop`) under
/// `packetization-mode=mode`.
async fn sprop_call(mode: u8, sprop: bool) -> Grown {
    grown_edited(
        CALL,
        "sendrecv",
        Some((96, "sendrecv")),
        &|offer| {
            offer.replace(
                "packetization-mode=1",
                &format!("packetization-mode={mode}"),
            )
        },
        &|section| {
            let extra = if sprop {
                format!(";sprop-parameter-sets={SPROP}")
            } else {
                String::new()
            };
            section.replace(
                "packetization-mode=1",
                &format!("packetization-mode={mode}{extra}"),
            )
        },
    )
    .await
}

fn far_video_address(call: &Grown) -> SocketAddr {
    sdp::parse_video_stream(&call.far_offer)
        .expect("video")
        .remote_rtp
}

fn far_endpoint(call: &Grown) -> EndpointId {
    let guard = call.engine.calls.get(CALL).expect("call");
    guard
        .far
        .as_ref()
        .expect("far")
        .video
        .expect("video")
        .rtp
        .id
}

/// Everything the caller is sent until a quiet moment.
async fn drain(socket: &UdpSocket) -> Vec<Vec<u8>> {
    let mut all = Vec::new();
    while let Some(datagram) = received(socket).await {
        all.push(datagram);
    }
    all
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idr_without_in_band_sets_reaches_the_caller_behind_the_far_partys_sprop_sets() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    assert!(
        call.engine.bridge().owns(far_endpoint(&call)),
        "the far video endpoint is armed"
    );
    for datagram in [
        far_rtp(10, 9_000, false, &P_SLICE),
        far_rtp(11, 12_000, true, &IDR),
        far_rtp(12, 15_000, true, &P_SLICE),
    ] {
        call.callee_video
            .send_to(&datagram, far)
            .await
            .expect("send");
    }
    let got = drain(&call.caller.video).await;
    assert_eq!(got.len(), 4, "SPS, PPS, IDR and the next slice: {got:02x?}");
    let sps = fields(&got[0]);
    let pps = fields(&got[1]);
    assert_eq!(
        (sps.0, sps.1, sps.2, sps.3, sps.4, sps.5.as_slice()),
        (9, 12_000, FAR_SSRC, false, 96, &SPS[..]),
        "the SPS two before the IDR, on its timestamp, no marker"
    );
    assert_eq!(
        (pps.0, pps.1, pps.2, pps.3, pps.4, pps.5.as_slice()),
        (10, 12_000, FAR_SSRC, false, 96, &PPS[..])
    );
    assert_eq!(
        got[2],
        far_rtp(11, 12_000, true, &IDR),
        "the IDR is untouched"
    );
    assert_eq!(got[3], far_rtp(12, 15_000, true, &P_SLICE));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stream_returns_to_the_kernel_path_once_the_idr_is_through() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    let endpoint = far_endpoint(&call);
    call.callee_video
        .send_to(&far_rtp(10, 9_000, false, &P_SLICE), far)
        .await
        .expect("send");
    call.callee_video
        .send_to(&far_rtp(11, 12_000, true, &IDR), far)
        .await
        .expect("send");
    // The stream stays on the bridge until it is well past the IDR, so no late original of the two
    // numbers the sets took can reach the caller by another path.
    call.engine.sweep_video_injectors();
    assert!(call.engine.bridge().owns(endpoint));
    for sequence in 12..=(11 + SETTLE_PACKETS as u16) {
        let slice = far_rtp(sequence, 15_000, false, &P_SLICE);
        call.callee_video.send_to(&slice, far).await.expect("send");
    }
    assert_eq!(
        drain(&call.caller.video).await.len(),
        3 + usize::try_from(SETTLE_PACKETS).expect("positive")
    );
    // One sweep puts the Forward rule back, the next lets the bridge flow go.
    call.engine.sweep_video_injectors();
    call.engine.sweep_video_injectors();
    assert!(
        !call.engine.bridge().owns(endpoint),
        "the bridge has let the endpoint go"
    );
    assert!(call
        .engine
        .calls
        .get(CALL)
        .expect("call")
        .video
        .injector
        .is_none());
    let later = far_rtp(200, 18_000, true, &P_SLICE);
    call.callee_video.send_to(&later, far).await.expect("send");
    assert_eq!(
        received(&call.caller.video).await.expect("relayed"),
        later,
        "the next packet is relayed, with its own sequence number"
    );
    // The recorded flows still hold the Forward rule the go-live keyframe request reads.
    let guard = call.engine.calls.get(CALL).expect("call");
    assert!(guard
        .video
        .flows
        .iter()
        .any(|(id, action)| *id == endpoint && matches!(action, FlowAction::Forward(_))));
    // A later renegotiation does not arm it again: the caller has the sets.
    drop(guard);
    call.engine
        .install_video_relay(CALL, &ProfileFlags::default(), false)
        .expect("reinstall");
    assert!(!call.engine.bridge().owns(endpoint));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sets_the_far_party_sent_in_band_are_preferred_to_its_sprop() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    for datagram in [
        far_rtp(10, 9_000, false, &IN_BAND_SPS),
        far_rtp(11, 9_000, false, &IN_BAND_PPS),
        far_rtp(12, 10_000, false, &P_SLICE),
        far_rtp(13, 12_000, true, &IDR),
    ] {
        call.callee_video
            .send_to(&datagram, far)
            .await
            .expect("send");
    }
    // Nothing before the IDR is delivered as sent: the sets come again under the two numbers
    // before it, from the far party's own packets and not from its SDP.
    let got = drain(&call.caller.video).await;
    assert_eq!(got.len(), 3, "{got:02x?}");
    assert_eq!(
        (fields(&got[0]).0, fields(&got[0]).1, fields(&got[0]).5),
        (11, 12_000, IN_BAND_SPS.to_vec())
    );
    assert_eq!(
        (fields(&got[1]).0, fields(&got[1]).5),
        (12, IN_BAND_PPS.to_vec())
    );
    assert_eq!(got[2], far_rtp(13, 12_000, true, &IDR));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_packet_older_than_the_idr_is_dropped_after_the_sets_were_sent() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    for datagram in [
        far_rtp(11, 12_000, false, &IDR),
        // Reordered: it was sent before the IDR and would collide with the injected sets.
        far_rtp(10, 9_000, false, &P_SLICE),
        far_rtp(12, 12_000, true, &[0x41, 0x9A, 0x01]),
    ] {
        call.callee_video
            .send_to(&datagram, far)
            .await
            .expect("send");
    }
    let got = drain(&call.caller.video).await;
    let sequences: Vec<u16> = got.iter().map(|datagram| fields(datagram).0).collect();
    assert_eq!(sequences, [9, 10, 11, 12], "{got:02x?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_cannot_drive_the_injector_or_reach_the_caller() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    let (stranger, _) = phone_at(Ipv4Addr::new(127, 0, 0, 2)).await;
    stranger
        .send_to(&far_rtp(500, 1, true, &IDR), far)
        .await
        .expect("send");
    assert!(
        received(&call.caller.video).await.is_none(),
        "RTPBleed: the stranger's IDR is not relayed and starts nothing"
    );
    call.callee_video
        .send_to(&far_rtp(11, 12_000, true, &IDR), far)
        .await
        .expect("send");
    let got = drain(&call.caller.video).await;
    let sequences: Vec<u16> = got.iter().map(|datagram| fields(datagram).0).collect();
    assert_eq!(sequences, [9, 10, 11], "{got:02x?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_idr_in_two_seconds_forwards_anyway_asks_again_and_returns_to_the_kernel() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    let endpoint = far_endpoint(&call);
    call.callee_video
        .send_to(&far_rtp(10, 9_000, false, &P_SLICE), far)
        .await
        .expect("send");
    assert!(
        received(&call.caller.video).await.is_none(),
        "nothing the caller cannot decode is sent before an IDR"
    );
    // The go-live request names the stream the relay saw, even though a bridge carries it.
    call.engine.request_video_keyframes().await;
    let first = received(&call.callee_video_rtcp)
        .await
        .expect("the callee is asked once for a keyframe");
    assert_eq!(parse_picture_loss(&first).1, FAR_SSRC);

    for _ in 0..3 {
        call.engine.sweep_video_injectors();
    }
    call.callee_video
        .send_to(&far_rtp(11, 12_000, false, &P_SLICE), far)
        .await
        .expect("send");
    assert_eq!(
        received(&call.caller.video)
            .await
            .expect("forwarded anyway"),
        far_rtp(11, 12_000, false, &P_SLICE),
        "unchanged, with nothing injected"
    );
    call.engine.request_video_keyframes().await;
    let second = received(&call.callee_video_rtcp)
        .await
        .expect("one more request when the wait ran out");
    assert_eq!(parse_picture_loss(&second).1, FAR_SSRC);
    call.engine.sweep_video_injectors();
    call.engine.sweep_video_injectors();
    assert!(!call.engine.bridge().owns(endpoint));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packetization_mode_two_and_a_far_answer_without_sprop_are_not_armed() {
    for (mode, sprop) in [(2, true), (1, false), (0, false)] {
        let call = sprop_call(mode, sprop).await;
        let far = far_video_address(&call);
        assert!(
            !call.engine.bridge().owns(far_endpoint(&call)),
            "mode {mode}, sprop {sprop}"
        );
        let slice = far_rtp(10, 9_000, false, &P_SLICE);
        call.callee_video.send_to(&slice, far).await.expect("send");
        assert_eq!(
            received(&call.caller.video).await.expect("relayed at once"),
            slice
        );
        delete(&call.engine, CALL, None).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn packetization_mode_zero_with_sprop_is_armed() {
    let call = sprop_call(0, true).await;
    assert!(call.engine.bridge().owns(far_endpoint(&call)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_sprop_is_ignored_and_relays_as_before() {
    let call = grown_edited(
        CALL,
        "sendrecv",
        Some((96, "sendrecv")),
        &|text| text,
        &|section| {
            section.replace(
                "packetization-mode=1",
                "packetization-mode=1;sprop-parameter-sets=!!notbase64!!",
            )
        },
    )
    .await;
    assert!(!call.engine.bridge().owns(far_endpoint(&call)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_the_far_leg_or_the_call_mid_window_cancels_the_injector() {
    let call = sprop_call(1, true).await;
    let endpoint = far_endpoint(&call);
    assert!(call.engine.bridge().owns(endpoint));
    delete(&call.engine, CALL, Some("tag-b")).await;
    assert!(!call.engine.bridge().owns(endpoint), "the far leg is gone");
    {
        let guard = call.engine.calls.get(CALL).expect("the call stays");
        assert!(guard.video.injector.is_none());
    }
    // The sweep has nothing to do and nothing to trip over.
    call.engine.sweep_video_injectors();
    delete(&call.engine, CALL, None).await;
    assert!(call.engine.calls.get(CALL).is_none());
    assert!(!call.engine.bridge().owns(endpoint));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renegotiation_mid_window_arms_a_fresh_injector_and_the_old_one_stops() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    let endpoint = far_endpoint(&call);
    let before = call
        .engine
        .calls
        .get(CALL)
        .expect("call")
        .video
        .injector
        .clone()
        .expect("armed");
    call.engine
        .install_video_relay(CALL, &ProfileFlags::default(), false)
        .expect("reinstall");
    let after = call
        .engine
        .calls
        .get(CALL)
        .expect("call")
        .video
        .injector
        .clone()
        .expect("armed again");
    assert!(!Arc::ptr_eq(&before, &after));
    assert!(call.engine.bridge().owns(endpoint));
    call.callee_video
        .send_to(&far_rtp(11, 12_000, true, &IDR), far)
        .await
        .expect("send");
    assert_eq!(drain(&call.caller.video).await.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_injected_packets_decode_as_h264_in_wireshark() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    call.callee_video
        .send_to(&far_rtp(11, 12_000, true, &IDR), far)
        .await
        .expect("send");
    let got = drain(&call.caller.video).await;
    assert_eq!(got.len(), 3, "{got:02x?}");
    let Some(reading) = tshark_rtp_reading(&got) else {
        eprintln!("tshark/text2pcap not installed: the Wireshark cross-check was skipped");
        return;
    };
    assert!(!reading.contains("Malformed"), "{reading}");
    assert!(!reading.contains("Unknown"), "{reading}");
    assert_eq!(reading.matches("Sequence number:").count(), 3, "{reading}");
    for expected in [
        "Sequence number: 9",
        "Sequence number: 10",
        "Sequence number: 11",
        "= Type: NAL unit - Sequence parameter set (7)",
        "= Type: NAL unit - Picture parameter set (8)",
        "= Type: NAL unit - Coded slice of an IDR picture (5)",
        "Synchronization Source identifier: 0xfa120001",
        "Timestamp: 12000",
    ] {
        assert!(reading.contains(expected), "{expected} in {reading}");
    }
}

/// What Wireshark makes of `datagrams` as RTP with H.264 on dynamic payload type 96, or `None` when
/// it or `text2pcap` is not installed.
fn tshark_rtp_reading(datagrams: &[Vec<u8>]) -> Option<String> {
    use std::io::Write;
    let directory = std::env::temp_dir().join(format!("siphon-sprop-{}", std::process::id()));
    std::fs::create_dir_all(&directory).ok()?;
    let mut dump = String::new();
    for datagram in datagrams {
        for (row, chunk) in datagram.chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|octet| format!("{octet:02x}")).collect();
            dump.push_str(&format!("{:04x}  {}\n", row * 16, hex.join(" ")));
        }
        dump.push('\n');
    }
    let (text, pcap) = (directory.join("sprop.txt"), directory.join("sprop.pcap"));
    std::fs::File::create(&text)
        .ok()?
        .write_all(dump.as_bytes())
        .ok()?;
    let converted = std::process::Command::new("text2pcap")
        .args(["-u", "6001,6002"])
        .arg(&text)
        .arg(&pcap)
        .output()
        .ok()?;
    if !converted.status.success() {
        return None;
    }
    // Wireshark reads a preferences file from the home directory; the test gives it an empty one.
    let output = std::process::Command::new("tshark")
        .env("HOME", &directory)
        .env("XDG_CONFIG_HOME", &directory)
        .arg("-r")
        .arg(&pcap)
        .args([
            "-d",
            "udp.port==6002,rtp",
            "-o",
            "h264.dynamic.payload.type:96",
            "-V",
        ])
        .output()
        .ok()?;
    let reading = String::from_utf8_lossy(&output.stdout).into_owned();
    let _ = std::fs::remove_dir_all(&directory);
    output.status.success().then_some(reading)
}

fn armed_injector(call: &Grown) -> Arc<VideoInjector> {
    call.engine
        .calls
        .get(CALL)
        .expect("call")
        .video
        .injector
        .clone()
        .expect("armed")
}

/// Run the sweep's step for `injector` as a sweep that read it before a renegotiation or a park would.
fn stale_sweep(call: &Grown, injector: &Arc<VideoInjector>) {
    let mut guard = call.engine.calls.get_mut(CALL).expect("call");
    for tick in [Tick::Demote { timed_out: false }, Tick::Retire] {
        call.engine.act_on_tick(CALL, &mut guard, injector, tick);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sweep_that_read_the_injector_before_a_renegotiation_leaves_the_new_flow_alone() {
    let call = sprop_call(1, true).await;
    let endpoint = far_endpoint(&call);
    let old = armed_injector(&call);
    call.engine
        .install_video_relay(CALL, &ProfileFlags::default(), false)
        .expect("renegotiate");
    let new = armed_injector(&call);
    assert!(!Arc::ptr_eq(&old, &new));
    stale_sweep(&call, &old);
    assert!(!old.is_demoted(), "the stale injector was not acted on");
    assert!(
        call.engine.bridge().owns(endpoint),
        "the new flow keeps its bridge entry"
    );
    assert!(Arc::ptr_eq(&armed_injector(&call), &new));
    assert!(!new.is_demoted());
    assert!(!call.engine.calls.get(CALL).expect("call").video.sprop_spent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sweep_that_read_the_injector_before_a_park_leaves_the_parked_flow_alone() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    let old = armed_injector(&call);
    call.engine.park_video(CALL).expect("park");
    stale_sweep(&call, &old);
    assert!(!old.is_demoted());
    assert!(!call.engine.calls.get(CALL).expect("call").video.sprop_spent);
    call.callee_video
        .send_to(&far_rtp(10, 9_000, false, &P_SLICE), far)
        .await
        .expect("send");
    assert!(
        received(&call.caller.video).await.is_none(),
        "the far video is still parked"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idr_whose_sets_could_not_be_sent_asks_the_far_party_for_another_keyframe() {
    let call = sprop_call(1, true).await;
    let far = far_video_address(&call);
    // The stream is seen (so its SSRC is known) and held back.
    call.callee_video
        .send_to(&far_rtp(10, 9_000, false, &P_SLICE), far)
        .await
        .expect("send");
    assert!(received(&call.caller.video).await.is_none());
    call.engine.request_video_keyframes().await;
    assert!(
        received(&call.callee_video_rtcp).await.is_some(),
        "go-live request"
    );
    // What the bridge does when the sets cannot be sent.
    let injector = armed_injector(&call);
    let mut buffer = Vec::new();
    injector.admit(&far_rtp(20, 12_000, false, &IDR), &mut buffer);
    injector.abandon_idr();
    call.engine.sweep_video_injectors();
    call.engine.request_video_keyframes().await;
    let again = received(&call.callee_video_rtcp)
        .await
        .expect("asked again");
    assert_eq!(parse_picture_loss(&again).1, FAR_SSRC);
    // And the next IDR is served.
    call.callee_video
        .send_to(&far_rtp(30, 15_000, true, &IDR), far)
        .await
        .expect("send");
    let got = drain(&call.caller.video).await;
    let sequences: Vec<u16> = got.iter().map(|datagram| fields(datagram).0).collect();
    assert_eq!(sequences, [28, 29, 30], "{got:02x?}");
}

#[tokio::test]
async fn a_failed_parameter_set_send_holds_the_idr_back_and_the_next_idr_is_served() {
    use crate::srtp_bridge::{BridgeCallPlan, BridgeFlowPlan, SrtpBridge};
    let datapath = LatchLearningDatapath::new();
    let ingress = datapath.alloc_endpoint().await.expect("endpoint").id;
    let egress = datapath.alloc_endpoint().await.expect("endpoint").id;
    let (sink, sink_addr) = phone().await;
    let source: SocketAddr = (Ipv4Addr::new(127, 0, 0, 2), 5000).into();
    let bridge = SrtpBridge::new(datapath.clone());
    bridge.register(BridgeCallPlan {
        near_leg: None,
        far_leg: None,
        flows: vec![BridgeFlowPlan {
            endpoint: ingress,
            ingress_leg: None,
            egress_leg: None,
            accepted_source: SourceFilter::Exact(source.ip()),
            latch: false,
            out_endpoint: egress,
            out_dst: sink_addr,
        }],
    });
    let mut sets = siphon_rtp_media::h264::ParameterSets::new();
    sets.store(&SPS, true);
    sets.store(&PPS, false);
    let injector = Arc::new(VideoInjector::new(sets));
    assert!(bridge.attach_video_injector(ingress, injector.clone()));
    let packet = |data: Vec<u8>| RxPacket {
        endpoint: ingress,
        source,
        arrival: 0,
        data: bytes::Bytes::from(data),
    };
    datapath.fail_next_sends(1);
    bridge.handle(packet(far_rtp(20, 12_000, true, &IDR))).await;
    assert!(
        received(&sink).await.is_none(),
        "nothing of the IDR is forwarded without its sets"
    );
    assert!(!injector.is_settled());
    assert!(injector.take_retry(), "a keyframe is to be asked for");
    // The retry: the sets and the IDR, in order, under the numbers before the second IDR.
    bridge.handle(packet(far_rtp(30, 15_000, true, &IDR))).await;
    let got = drain(&sink).await;
    let sequences: Vec<u16> = got.iter().map(|datagram| fields(datagram).0).collect();
    assert_eq!(sequences, [28, 29, 30], "{got:02x?}");
    assert_eq!(fields(&got[0]).5, SPS);
    assert_eq!(fields(&got[1]).5, PPS);
}
