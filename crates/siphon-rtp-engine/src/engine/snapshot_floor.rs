//! HA checkpoint and restore of an MCPTT floor stream (3GPP TS 24.380 §8) of a two-party call.
//!
//! The stream is terminated on one engine endpoint per party and served by the call-floor actor
//! ([`crate::call_floor`]), which alone owns its state: the checkpoint asks it over a oneshot and the
//! restore hands it back through the registration, so nothing is shared. What a standby needs to
//! resume exactly where the primary stopped is carried in [`FloorSnapshot`]; this module converts
//! it to and from the actor's types and enforces the two rules a failover must not break.
//!
//! * **No IV reuse.** The primary keeps sending floor control between the checkpoint and its
//!   failure, so the index in the snapshot is already behind. RFC 7714 §9.4 forbids protecting two
//!   packets under one key with the same index (the GCM IV would repeat, which breaks both
//!   confidentiality and authenticity), so the standby starts [`SEND_INDEX_MARGIN`] past it. A
//!   margin that would leave the 31-bit index space refuses the restore; it never wraps.
//! * **No re-learning.** The learn-once latch comes back pinned to the source the primary had
//!   learned (docs/security-and-nat.md §4 layer 5h), and the replay state of each key comes back at
//!   the highest index received, so a failover neither lets the first sender win the stream nor
//!   accepts the phone's last packets twice (RFC 3711 §3.3.2).

use std::net::SocketAddr;

use siphon_rtp_datapath::Datapath;
use siphon_rtp_srtp::srtcp_gcm::{FloorMasterKey, MAX_SEND_INDEX};
use zeroize::Zeroize;

use crate::call_floor::{CallFloorLeg, FloorRestore};
use crate::ha::{self, FloorKeySnapshot, FloorReceivedSnapshot, FloorSnapshot};

use super::snapshot::{restore_source_filter, source_filter_snapshot};
use super::{ClientId, Engine};

/// How far past the checkpointed index a standby starts sending (RFC 7714 §9.4).
///
/// The primary sends floor control at a few packets a second at most, and a checkpoint is
/// refreshed on the controller's schedule, so the gap between the last checkpoint and the failure is
/// seconds to minutes. 2^16 indices cover more than 18 hours at one packet per second, or 11
/// minutes at a hundred, while costing 0.003 % of the 2^31 index space.
pub(super) const SEND_INDEX_MARGIN: u32 = 1 << 16;

/// A floor leg of a snapshot, converted and validated before anything is bound.
pub(super) struct PreparedFloor {
    pub(super) snapshot: FloorSnapshot,
    keys: Vec<FloorMasterKey>,
    send_index: u32,
}

/// The snapshot form of `keys`: hex, oldest first.
pub(super) fn key_snapshots(keys: &[FloorMasterKey]) -> Vec<FloorKeySnapshot> {
    keys.iter()
        .map(|key| FloorKeySnapshot {
            mki: key.mki,
            master_key_hex: ha::to_hex(&key.master_key),
            master_salt_hex: ha::to_hex(&key.master_salt),
        })
        .collect()
}

/// Decode `N` octets of secret hex. The intermediate buffer is wiped before it is freed, and a
/// length mismatch yields `None` (3GPP TS 33.180 §9.4: the keys are secrets).
fn secret_from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut bytes = ha::from_hex(text)?;
    let array = <[u8; N]>::try_from(bytes.as_slice()).ok();
    bytes.zeroize();
    array
}

fn restore_keys(keys: &[FloorKeySnapshot]) -> Result<Vec<FloorMasterKey>, String> {
    keys.iter()
        .map(|key| {
            let mut master_key = secret_from_hex::<16>(&key.master_key_hex)
                .ok_or("floor key is not 16 octets of hex")?;
            let Some(mut master_salt) = secret_from_hex::<14>(&key.master_salt_hex) else {
                master_key.zeroize();
                return Err("floor salt is not 14 octets of hex".to_string());
            };
            let restored = FloorMasterKey {
                mki: key.mki,
                master_key,
                master_salt,
            };
            // The struct holds copies; wipe the locals they came from.
            master_key.zeroize();
            master_salt.zeroize();
            Ok(restored)
        })
        .collect()
}

/// The first index a standby may send under, or `None` when the margin would leave the 31-bit index
/// space (RFC 7714 §9.4: the index never wraps).
fn resumed_send_index(checkpointed: u32) -> Option<u32> {
    checkpointed
        .checked_add(SEND_INDEX_MARGIN)
        .filter(|index| *index <= MAX_SEND_INDEX)
}

/// Validate a snapshot's floor stream: the key set must decode and a keyed stream must have room
/// for the index margin. Refuses with a reason; nothing is bound yet.
pub(super) fn prepare(snapshot: &FloorSnapshot) -> Result<PreparedFloor, String> {
    let keys = restore_keys(&snapshot.keys)?;
    let send_index = if keys.is_empty() {
        0
    } else {
        resumed_send_index(snapshot.send_index).ok_or_else(|| {
            format!(
                "the floor stream's SRTCP index {} leaves no room for the {} margin that keeps \
                 the standby from reusing an index (RFC 7714 section 9.4)",
                snapshot.send_index, SEND_INDEX_MARGIN
            )
        })?
    };
    Ok(PreparedFloor {
        snapshot: snapshot.clone(),
        keys,
        send_index,
    })
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// The floor stream of the leg `tag` of `call_id`, read from the actor that serves it. `Ok(None)`
    /// when the leg has no served stream (the answerer declined it); an error when the actor does not
    /// answer, because a checkpoint without a stream the call has would restore silently without it.
    pub(super) async fn floor_snapshot(
        &self,
        call_id: &str,
        tag: &str,
        local: SocketAddr,
        remote: Option<SocketAddr>,
    ) -> Result<Option<FloorSnapshot>, String> {
        let floors = self.conference.floors();
        if !floors.has_leg(call_id, tag) {
            return Ok(None);
        }
        let state = floors.leg_state(call_id, tag).await.ok_or_else(|| {
            "the floor stream did not report its state, so a standby would resume without it"
                .to_string()
        })?;
        Ok(Some(FloorSnapshot {
            local,
            remote,
            accepted_source: source_filter_snapshot(state.accepted_source),
            destination: state.destination,
            latched: state.latched,
            ssrc: state.ssrc,
            fmtp: floors.fmtp(call_id, tag),
            keys: key_snapshots(&state.keys),
            send_index: state.send_index,
            received: state
                .received
                .iter()
                .map(|&(mki, index)| FloorReceivedSnapshot { mki, index })
                .collect(),
        }))
    }

    /// Serve a restored floor stream on its freshly bound endpoint, for the controller `client` that
    /// owns the restored call, resuming the latch, SSRC, keys, index and replay state.
    pub(super) fn register_restored_floor(
        &self,
        client: ClientId,
        call_id: &str,
        tag: &str,
        endpoint: siphon_rtp_datapath::EndpointId,
        prepared: PreparedFloor,
    ) {
        let PreparedFloor {
            snapshot,
            keys,
            send_index,
        } = prepared;
        self.conference.floors().register(
            &self.datapath,
            CallFloorLeg {
                call_id: call_id.to_string(),
                tag: tag.to_string(),
                endpoint,
                destination: snapshot.destination,
                accepted_source: restore_source_filter(snapshot.accepted_source),
                // The phone has seen this SSRC; a standby that minted another would look like a new
                // source to it (RFC 3550 §8.2).
                ssrc: snapshot.ssrc,
                events: self.app_event_queue(client),
                keys,
                fmtp: snapshot.fmtp,
                restore: Some(FloorRestore {
                    latched: snapshot.latched,
                    send_index,
                    received: snapshot
                        .received
                        .iter()
                        .map(|received| (received.mki, received.index))
                        .collect(),
                }),
            },
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn snapshot(send_index: u32, keyed: bool) -> FloorSnapshot {
        FloorSnapshot {
            local: "192.0.2.10:30000".parse().unwrap(),
            remote: Some("192.0.2.1:4100".parse().unwrap()),
            accepted_source: ha::SourceFilterSnapshot::Any,
            destination: "192.0.2.1:4100".parse().unwrap(),
            latched: None,
            ssrc: 7,
            fmtp: None,
            keys: if keyed {
                key_snapshots(&[FloorMasterKey {
                    mki: 3,
                    master_key: [0x11; 16],
                    master_salt: [0x22; 14],
                }])
            } else {
                Vec::new()
            },
            send_index,
            received: Vec::new(),
        }
    }

    #[test]
    fn the_margin_moves_a_keyed_stream_past_the_checkpointed_index() {
        let prepared = prepare(&snapshot(41, true)).unwrap();
        assert_eq!(prepared.send_index, 41 + SEND_INDEX_MARGIN);
        assert_eq!(prepared.keys[0].mki, 3);
        assert_eq!(prepared.keys[0].master_salt, [0x22; 14]);
    }

    #[test]
    fn an_index_that_leaves_no_room_for_the_margin_refuses_instead_of_wrapping() {
        let last_that_fits = MAX_SEND_INDEX - SEND_INDEX_MARGIN;
        assert_eq!(
            prepare(&snapshot(last_that_fits, true)).unwrap().send_index,
            MAX_SEND_INDEX
        );
        let error = prepare(&snapshot(last_that_fits + 1, true)).err().unwrap();
        assert!(error.contains("RFC 7714"), "{error}");
        // The index of a stream in the clear means nothing and never refuses.
        assert_eq!(prepare(&snapshot(u32::MAX, false)).unwrap().send_index, 0);
    }

    #[test]
    fn a_malformed_key_refuses_the_restore() {
        let mut broken = snapshot(0, true);
        broken.keys[0].master_key_hex = "00".into();
        assert!(prepare(&broken).is_err());
        let mut odd = snapshot(0, true);
        odd.keys[0].master_salt_hex = "abc".into();
        assert!(prepare(&odd).is_err());
    }

    #[test]
    fn secrets_decode_to_a_fixed_array_and_refuse_a_wrong_length() {
        let key: [u8; 16] = secret_from_hex(&ha::to_hex(&[0x11; 16])).unwrap();
        assert_eq!(key, [0x11; 16]);
        assert!(secret_from_hex::<16>(&ha::to_hex(&[0x11; 15])).is_none());
        assert!(secret_from_hex::<16>("zz").is_none());
        assert!(secret_from_hex::<16>("abc").is_none());
    }

    #[test]
    fn zeroizing_a_key_snapshot_empties_both_hex_strings() {
        use zeroize::Zeroize as _;
        let mut keys = snapshot(0, true).keys;
        assert_eq!(keys[0].master_key_hex.len(), 32);
        keys[0].zeroize();
        assert!(keys[0].master_key_hex.is_empty());
        assert!(keys[0].master_salt_hex.is_empty());
        assert_eq!(keys[0].mki, 3, "the MKI is wire data and stays");
    }

    #[test]
    fn key_material_never_reaches_a_log_through_debug() {
        let text = format!("{:?}", snapshot(0, true).keys);
        assert!(!text.contains("1111"), "{text}");
        assert!(text.contains("redacted"));
    }
}
