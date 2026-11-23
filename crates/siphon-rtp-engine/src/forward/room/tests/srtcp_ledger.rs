//! No (key, SSRC, index) triple is ever sealed twice (RFC 7714 §8, §9.4): the GCM IV is the session
//! salt XOR (SSRC, SRTCP index), so a repeat under one key breaks confidentiality and integrity. The
//! send index belongs to the key, whichever seat, room, stream or rejoin sends under it.

use super::preserve::{media_key, preserve_room};
use super::*;
use crate::srtcp_ledger::SrtcpLedger;
use siphon_rtp_media::rtcp;
use siphon_rtp_proto::RtcpAppStream;
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, SrtcpGcmContext};
use std::collections::HashSet;
use std::sync::Arc;

/// `(key material, SSRC, index)` of a sealed SRTCP datagram: the fingerprint of the key it names (by
/// its MKI among `keys`), the sender SSRC in the clear header, and the index of the E|index word.
fn triple(datagram: &[u8], keys: &[FloorMasterKey]) -> ([u8; 20], u32, u32) {
    let mki = u32::from_be_bytes(datagram[datagram.len() - 4..].try_into().unwrap());
    let key = keys.iter().find(|key| key.mki == mki).unwrap();
    let ssrc = u32::from_be_bytes(datagram[4..8].try_into().unwrap());
    let word = u32::from_be_bytes(
        datagram[datagram.len() - 8..datagram.len() - 4]
            .try_into()
            .unwrap(),
    );
    (key.fingerprint(), ssrc, word & 0x7FFF_FFFF)
}

#[track_caller]
fn assert_unique(triples: &[([u8; 20], u32, u32)]) {
    let mut seen = HashSet::new();
    for triple in triples {
        assert!(
            seen.insert(*triple),
            "(key, SSRC {:#x}, index {}) was sealed twice: {triples:?}",
            triple.1,
            triple.2
        );
    }
}

fn report(ssrc: u32) -> Vec<u8> {
    let mut buffer = [0u8; 64];
    let length =
        rtcp::write_sender_report(ssrc, 0x0000_0001_8000_0000, 320, 1, 62, &[], &mut buffer)
            .unwrap();
    buffer[..length].to_vec()
}

/// What seat `index`'s phone sends: a report sealed under its own key, on a context of its own.
fn from_source(phone: &mut SrtcpGcmContext, ssrc: u32) -> RxPacket {
    let mut wire = Vec::new();
    phone.protect(&report(ssrc), true, &mut wire).unwrap();
    rx(1, 0, wire)
}

const TALKER_SSRC: u32 = 0xA0A0_A0A0;

/// A keyed preserve room: seat 1 is the source, the others receive under `media_key(index)`.
fn keyed_room(ledger: Arc<SrtcpLedger>, seats: u8) -> ForwardRoom {
    let mut room = ForwardRoom::with_ledger(
        "group-1".to_string(),
        preserve_room(1).codec().clone(),
        ledger,
    );
    for index in 1..=seats {
        let mut config = seat_config(index);
        config.media_srtcp = vec![media_key(index)];
        room.add_seat(config, 0).unwrap();
    }
    room.set_source(Some("seat-1")).unwrap();
    room
}

/// The datagrams the room sends seat 2 for `count` reports of the talker (SSRC `TALKER_SSRC`), each on
/// a fresh index of the talker's own context.
fn reseal(room: &mut ForwardRoom, talker: &mut SrtcpGcmContext, count: usize) -> Vec<Vec<u8>> {
    let mut sealed = Vec::new();
    for _ in 0..count {
        let packet = from_source(talker, TALKER_SSRC);
        assert_eq!(room.ingest(&packet), Ingress::Accepted);
        for (endpoint, _, datagram) in forwarded(room, &packet) {
            if endpoint == EndpointId(2) {
                sealed.push(datagram);
            }
        }
    }
    sealed
}

#[test]
fn a_seat_that_leaves_and_rejoins_with_its_key_does_not_restart_at_index_zero() {
    let keys = [media_key(2)];
    let mut room = keyed_room(Arc::default(), 3);
    let mut talker = super::preserve::phone(1);
    let mut triples: Vec<_> = reseal(&mut room, &mut talker, 3)
        .iter()
        .map(|datagram| triple(datagram, &keys))
        .collect();
    assert!(room.remove_seat("seat-2"));
    let mut back = seat_config(2);
    back.media_srtcp = vec![media_key(2)];
    room.add_seat(back, 0).unwrap();
    triples.extend(
        reseal(&mut room, &mut talker, 3)
            .iter()
            .map(|datagram| triple(datagram, &keys)),
    );
    assert_eq!(triples.len(), 6);
    assert_unique(&triples);
}

#[test]
fn one_client_key_seated_in_two_rooms_never_repeats_an_index() {
    // The talker's SSRC is the same in both groups (one UE in two groups): the resealed packets
    // differ in nothing but the index.
    let ledger: Arc<SrtcpLedger> = Arc::default();
    let keys = [media_key(2)];
    let (mut first, mut second) = (keyed_room(ledger.clone(), 2), keyed_room(ledger, 2));
    let mut talker = super::preserve::phone(1);
    let mut triples = Vec::new();
    for _ in 0..3 {
        for room in [&mut first, &mut second] {
            triples.extend(
                reseal(room, &mut talker, 1)
                    .iter()
                    .map(|datagram| triple(datagram, &keys)),
            );
        }
    }
    assert_eq!(triples.len(), 6);
    assert_unique(&triples);
}

#[test]
fn a_floor_stream_and_a_media_stream_under_one_key_never_repeat_an_index() {
    // One key per client covers its floor and its media RTCP (TS 33.180 §9.4.2). Both streams use the
    // seat's SSRC unless the controller names one.
    let keys = [media_key(2)];
    let mut room = ForwardRoom::new("group-1".to_string(), preserve_room(1).codec().clone());
    let mut config = seat_config(2);
    config.media_srtcp = vec![media_key(2)];
    config.floor = Some(FloorConfig {
        endpoint: EndpointId(102),
        destination: address("192.0.2.2:4100"),
        accepted_source: SourceFilter::Any,
        ice_gated: false,
        keys: vec![media_key(2)],
    });
    room.add_seat(config, 0).unwrap();
    let mut triples = Vec::new();
    for _ in 0..3 {
        for stream in [RtcpAppStream::Floor, RtcpAppStream::Audio] {
            let request = AppRequest {
                stream,
                ssrc: None,
                name: *b"MCPT",
                subtype: 1,
                payload: vec![0, 1, 2, 3],
            };
            room.send_app(
                &AppTarget::Seat("seat-2".to_string()),
                &request,
                |_, _, datagram| {
                    triples.push(triple(datagram, &keys));
                },
            )
            .unwrap();
        }
    }
    assert_eq!(triples.len(), 6);
    assert_unique(&triples);
}

#[test]
fn unkeying_and_keying_a_seat_again_continues_the_index() {
    let keys = [media_key(2)];
    let mut room = keyed_room(Arc::default(), 2);
    let mut talker = super::preserve::phone(1);
    let mut triples: Vec<_> = reseal(&mut room, &mut talker, 2)
        .iter()
        .map(|datagram| triple(datagram, &keys))
        .collect();
    room.set_media_srtcp_keys("seat-2", &[]).unwrap();
    room.set_media_srtcp_keys("seat-2", &keys).unwrap();
    triples.extend(
        reseal(&mut room, &mut talker, 2)
            .iter()
            .map(|datagram| triple(datagram, &keys)),
    );
    assert_eq!(triples.len(), 4);
    assert_unique(&triples);
}

#[test]
fn a_rekey_back_to_an_earlier_key_continues_where_that_key_stopped() {
    let (first, second) = (
        media_key(2),
        FloorMasterKey::from_salt_96(12, [0x77; 16], &[0x78; 12]),
    );
    let keys = [first.clone(), second.clone()];
    let mut room = keyed_room(Arc::default(), 2);
    let mut talker = super::preserve::phone(1);
    let mut triples: Vec<_> = reseal(&mut room, &mut talker, 2)
        .iter()
        .map(|datagram| triple(datagram, &keys))
        .collect();
    room.set_media_srtcp_keys("seat-2", &[first.clone(), second])
        .unwrap();
    triples.extend(
        reseal(&mut room, &mut talker, 2)
            .iter()
            .map(|datagram| triple(datagram, &keys)),
    );
    room.set_media_srtcp_keys("seat-2", &[first]).unwrap();
    triples.extend(
        reseal(&mut room, &mut talker, 2)
            .iter()
            .map(|datagram| triple(datagram, &keys)),
    );
    assert_eq!(triples.len(), 6);
    assert_unique(&triples);
}

#[test]
fn the_index_stops_at_the_last_value_and_the_room_refuses_to_send_rather_than_wrap() {
    let keys = [media_key(2)];
    let ledger: Arc<SrtcpLedger> = Arc::default();
    ledger
        .counter_for(&keys[0])
        .raise_to(siphon_rtp_srtp::srtcp_gcm::MAX_SEND_INDEX - 1);
    let mut room = keyed_room(ledger, 2);
    let mut talker = super::preserve::phone(1);
    let sealed = reseal(&mut room, &mut talker, 4);
    assert_eq!(sealed.len(), 2, "the last two indices go out, then nothing");
    let triples: Vec<_> = sealed
        .iter()
        .map(|datagram| triple(datagram, &keys))
        .collect();
    assert_eq!(triples[1].2, siphon_rtp_srtp::srtcp_gcm::MAX_SEND_INDEX);
    assert_unique(&triples);
}

#[test]
fn once_a_checkpoint_exists_a_key_that_reaches_its_lease_is_refused_until_the_next_checkpoint() {
    let ledger: Arc<SrtcpLedger> = Arc::default();
    let keys = [media_key(2)];
    let mut room = keyed_room(ledger.clone(), 2);
    let mut talker = super::preserve::phone(1);
    // No checkpoint, no lease: the room seals as long as it is asked.
    assert_eq!(reseal(&mut room, &mut talker, 6).len(), 6);
    let exported = ledger.checkpoint(8, Some(7));
    assert!(exported.entries.iter().any(|entry| entry.next_index == 6));
    // Half the window (4) later the key is due, once.
    assert_eq!(reseal(&mut room, &mut talker, 4).len(), 4);
    assert_eq!(ledger.take_due(), 1);
    assert_eq!(ledger.take_due(), 0);
    // The lease is 6 + 8 = 14: four more go, then nothing, however often the room is asked.
    let mut sealed: Vec<_> = reseal(&mut room, &mut talker, 4)
        .iter()
        .map(|datagram| triple(datagram, &keys))
        .collect();
    assert_eq!(sealed.len(), 4);
    assert!(
        reseal(&mut room, &mut talker, 20).is_empty(),
        "never past the lease"
    );
    assert!(ledger.lease_refused() >= 20, "each refusal is counted");
    // The next checkpoint extends it by a margin and the room goes on.
    let second = ledger.checkpoint(8, None);
    assert!(
        reseal(&mut room, &mut talker, 3).is_empty(),
        "an export alone extends nothing"
    );
    assert_eq!(ledger.confirm(&second.generation, 8), Ok(true));
    sealed.extend(
        reseal(&mut room, &mut talker, 3)
            .iter()
            .map(|datagram| triple(datagram, &keys)),
    );
    assert_eq!(sealed.len(), 7);
    assert_unique(&sealed);
    assert_eq!(
        sealed.last().unwrap().2,
        14 + 2,
        "carried on from the lease, nothing reissued"
    );
}
