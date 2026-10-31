#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench harness: a panic reports failure"
)]

//! The cost of MCPTT floor control (3GPP TS 24.380) in a forwarding room, with no sockets: one
//! Floor Request from the floor stream to its `rtcp_app` event, and one room-wide `send_rtcp_app`
//! at 500 seats. The event itself allocates (its name, tag and payload are owned strings the
//! controller connection serialises); the send path allocates nothing. Each is measured with the
//! floor stream in the clear and keyed with AEAD_AES_128_GCM SRTCP (3GPP TS 33.180 §9.4): the keyed
//! numbers are the extra per-packet cost a protected floor stream pays.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use siphon_rtp_datapath::{EndpointId, RxPacket, SourceFilter};
use siphon_rtp_engine::app_events::AppEventQueue;
use siphon_rtp_engine::forward::{
    AppRequest, AppTarget, FloorConfig, ForwardRoom, ForwardSeatConfig, RoomCodec,
};
use siphon_rtp_engine::metrics::Metrics;
use siphon_rtp_engine::sdp;
use siphon_rtp_proto::RtcpAppStream;
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SrtcpGcmContext};

const SEATS: usize = 500;

/// TS 24.380 §8.2.4 Floor Request.
const FLOOR_REQUEST: [u8; 16] = [
    0x80, 0xCC, 0x00, 0x03, 0x11, 0x22, 0x33, 0x44, 0x4D, 0x43, 0x50, 0x54, 0x00, 0x02, 0x05, 0x00,
];

fn room_of(seats: usize, queue: &AppEventQueue, keys: &[FloorMasterKey]) -> ForwardRoom {
    let offer = "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n\
                 m=audio 4000 RTP/AVP 96\r\na=rtpmap:96 AMR-WB/16000\r\na=fmtp:96 octet-align=1\r\n";
    let codecs = sdp::parse(offer).unwrap().audio_codecs();
    let (codec, _) = RoomCodec::from_offer(&codecs).unwrap();
    let mut room = ForwardRoom::new("bench".to_string(), codec);
    for index in 0..seats {
        let audio: SocketAddr = format!("192.0.2.{}:{}", 1 + index % 250, 4000 + index)
            .parse()
            .unwrap();
        let floor: SocketAddr = format!("192.0.2.{}:{}", 1 + index % 250, 8000 + index)
            .parse()
            .unwrap();
        room.add_seat(
            ForwardSeatConfig {
                tag: format!("seat-{index}"),
                endpoint: EndpointId(index as u64 + 1),
                egress_destination: audio,
                accepted_source: SourceFilter::Any,
                latch: true,
                audio_payload_type: 96,
                telephone_event: None,
                secure: None,
                secure_pending: false,
                ice_pending: false,
                egress_ssrc: 0xE000_0000 + index as u32,
                initial_sequence: 0,
                initial_timestamp: 0,
                floor: Some(FloorConfig {
                    endpoint: EndpointId(10_000 + index as u64),
                    destination: floor,
                    accepted_source: SourceFilter::Any,
                    ice_gated: false,
                    keys: keys.to_vec(),
                }),
                app_events: Some(queue.clone()),
            },
            0,
        )
        .unwrap();
    }
    room
}

fn floor_key() -> FloorMasterKey {
    FloorMasterKey::from_salt_96(7, [0x11; 16], &[0x22; 12])
}

fn floor_costs(criterion: &mut Criterion) {
    let queue = AppEventQueue::new(4096, Arc::new(Metrics::new()));
    let mut room = room_of(SEATS, &queue, &[]);
    let mut keyed_room = room_of(SEATS, &queue, &[floor_key()]);
    let received = queue.receiver();

    let packet = RxPacket {
        endpoint: EndpointId(10_000),
        source: "192.0.2.1:8000".parse().unwrap(),
        arrival: 1_000_000,
        data: Bytes::from(FLOOR_REQUEST.to_vec()),
    };
    // The first datagram learns the source; the loop below is the steady state.
    room.ingest(&packet);
    received.try_iter().for_each(drop);

    let mut group = criterion.benchmark_group("forward_floor");
    group.bench_function("floor_request_to_event", |bencher| {
        bencher.iter(|| {
            room.ingest(black_box(&packet));
            black_box(received.try_recv().unwrap())
        });
    });

    // A keyed stream refuses a repeated index (RFC 3711 §3.3.2), so every iteration gets a fresh
    // protected packet from the phone's side; building it is outside the timing.
    let mut phone = SrtcpGcmContext::new(&[floor_key()]).unwrap();
    let mut protect = move || {
        let mut wire = Vec::new();
        phone.protect(&FLOOR_REQUEST, true, &mut wire).unwrap();
        RxPacket {
            endpoint: EndpointId(10_000),
            source: "192.0.2.1:8000".parse().unwrap(),
            arrival: 1_000_000,
            data: Bytes::from(wire),
        }
    };
    keyed_room.ingest(&protect());
    received.try_iter().for_each(drop);
    group.bench_function("floor_request_to_event_keyed", |bencher| {
        bencher.iter_batched(
            &mut protect,
            |packet| {
                keyed_room.ingest(black_box(&packet));
                black_box(received.try_recv().unwrap())
            },
            criterion::BatchSize::SmallInput,
        );
    });

    let request = AppRequest {
        stream: RtcpAppStream::Floor,
        ssrc: None,
        name: *b"MCPT",
        subtype: 17,
        payload: vec![
            0x01, 0x02, 0x00, 0x1E, 0x0E, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00,
        ],
    };
    let everyone = AppTarget::Room { except: Vec::new() };
    group.bench_function("send_rtcp_app_room_wide_500_seats", |bencher| {
        bencher.iter(|| {
            let mut bytes = 0usize;
            room.send_app(black_box(&everyone), black_box(&request), |_, _, data| {
                bytes += data.len();
            })
            .unwrap();
            black_box(bytes)
        });
    });
    group.bench_function("send_rtcp_app_room_wide_500_seats_keyed", |bencher| {
        bencher.iter(|| {
            let mut bytes = 0usize;
            keyed_room
                .send_app(black_box(&everyone), black_box(&request), |_, _, data| {
                    bytes += data.len();
                })
                .unwrap();
            black_box(bytes)
        });
    });
    group.finish();
}

criterion_group!(benches, floor_costs);
criterion_main!(benches);
