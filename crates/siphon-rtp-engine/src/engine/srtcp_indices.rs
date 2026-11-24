//! HA of the SRTCP send-index ledger: the `checkpoint_srtcp_indices` and `restore_srtcp_indices`
//! verbs (RFC 7714 §8, §9.4; [`crate::srtcp_ledger`]).
//!
//! The blob is opaque to the controller and owned here: JSON carrying a version and, per key that has
//! sent, its fingerprint (hex, an HMAC under the key, so it names the key without revealing it and is
//! the same on every node) and the next index it will send. A standby seeds each counter
//! [`SEND_INDEX_MARGIN`] past the checkpointed index, the same margin and for the same reason as a
//! two-party floor call's (`snapshot_floor`): the primary went on sending between the checkpoint and
//! its failure, and a GCM IV must never repeat under a key. An import never lowers a counter. A blob
//! is read whole and refused whole: nothing is applied from one that does not parse.

use serde::{Deserialize, Serialize};
use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, Event};
use siphon_rtp_srtp::srtcp_gcm::{FINGERPRINT_LEN, ORIGIN_TAG_LEN};

use crate::ha;
use crate::srtcp_ledger::{LedgerCheckpoint, LedgerEntry, POISONED_REASON};

use super::snapshot_floor::SEND_INDEX_MARGIN;
use super::{error_result, Engine};

/// The blob's format version.
const BLOB_VERSION: u32 = 2;

/// The first format, which has no origin tag: read, and always treated as another engine's blob.
const BLOB_VERSION_UNTAGGED: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Blob {
    version: u32,
    /// Which checkpoint this is: an opaque token unique across nodes, which the controller confirms by
    /// once it has stored the blob.
    generation: String,
    /// The ceiling below which any key the blob does not list has sent: a standby seeds every key it
    /// holds or installs that the blob does not name at it (see [`crate::srtcp_ledger`]).
    unlisted_ceiling: u32,
    entries: Vec<BlobEntry>,
    /// Hex of the HMAC under the exporting engine's secret that proves, to that engine only, that it
    /// exported this blob (version 2). Absent in version 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin_tag: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct BlobEntry {
    fingerprint: String,
    next_index: u32,
}

/// The blob for `entries`.
fn encode(checkpoint: &LedgerCheckpoint) -> Result<String, String> {
    let blob = Blob {
        version: BLOB_VERSION,
        generation: checkpoint.generation.clone(),
        unlisted_ceiling: checkpoint.unlisted_ceiling,
        entries: checkpoint
            .entries
            .iter()
            .map(|entry| BlobEntry {
                fingerprint: ha::to_hex(&entry.fingerprint),
                next_index: entry.next_index,
            })
            .collect(),
        origin_tag: checkpoint.origin_tag.as_ref().map(|tag| ha::to_hex(tag)),
    };
    serde_json::to_string(&blob).map_err(|error| error.to_string())
}

/// The entries of `text`, or why it is not a blob this engine reads.
pub fn decode(text: &str) -> Result<LedgerCheckpoint, String> {
    let blob: Blob = serde_json::from_str(text)
        .map_err(|error| format!("not an SRTCP index ledger: {error}"))?;
    if blob.version != BLOB_VERSION && blob.version != BLOB_VERSION_UNTAGGED {
        return Err(format!(
            "SRTCP index ledger version {} is not the {BLOB_VERSION_UNTAGGED} or {BLOB_VERSION} this engine reads",
            blob.version
        ));
    }
    let entries = blob
        .entries
        .into_iter()
        .map(|entry| {
            let fingerprint = ha::from_hex(&entry.fingerprint)
                .and_then(|bytes| <[u8; FINGERPRINT_LEN]>::try_from(bytes).ok())
                .ok_or_else(|| {
                    format!(
                        "fingerprint {:?} is not {FINGERPRINT_LEN} octets of hex",
                        entry.fingerprint
                    )
                })?;
            Ok(LedgerEntry {
                fingerprint,
                next_index: entry.next_index,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    // A version 1 blob carries no tag, whatever its text says: it cannot prove it is this engine's.
    let origin_tag = match (blob.version, blob.origin_tag) {
        (BLOB_VERSION, Some(text)) => Some(
            ha::from_hex(&text)
                .and_then(|bytes| <[u8; ORIGIN_TAG_LEN]>::try_from(bytes).ok())
                .ok_or_else(|| {
                    format!("origin tag {text:?} is not {ORIGIN_TAG_LEN} octets of hex")
                })?,
        ),
        _ => None,
    };
    Ok(LedgerCheckpoint {
        generation: blob.generation,
        entries,
        unlisted_ceiling: blob.unlisted_ceiling,
        origin_tag,
    })
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Export the SRTCP send-index ledger ([`siphon_rtp_proto::Command::CheckpointSrtcpIndices`]).
    /// Every entry is exported, and from here each counter has a lease a margin past its exported
    /// index; `client` is who the `srtcp_checkpoint_due` events go to.
    pub(super) fn checkpoint_srtcp_indices(&self, client: super::ClientId) -> CmdResult {
        if self.conference.srtcp_ledger().is_poisoned() {
            return error_result("checkpoint_srtcp_indices", &POISONED_REASON);
        }
        let checkpoint = self
            .conference
            .srtcp_ledger()
            .checkpoint(SEND_INDEX_MARGIN, Some(client.0));
        match encode(&checkpoint) {
            Ok(snapshot) => CmdResult::SrtcpIndices { snapshot },
            Err(reason) => error_result("checkpoint_srtcp_indices", &reason),
        }
    }

    /// The controller has stored checkpoint `generation`
    /// ([`siphon_rtp_proto::Command::ConfirmSrtcpIndices`]): the leases follow it. A confirmation of an
    /// older generation than the last confirmed one is ignored and still answers `ok`.
    pub(super) fn confirm_srtcp_indices(&self, generation: &str) -> CmdResult {
        match self
            .conference
            .srtcp_ledger()
            .confirm(generation, SEND_INDEX_MARGIN)
        {
            Ok(_) => super::ok_empty(),
            Err(reason) => error_result("confirm_srtcp_indices", &reason),
        }
    }

    /// Run the ledger's housekeeping (see [`crate::srtcp_ledger`]): the opt-in retention clock, and
    /// the check for counters that have used half of their lease window, which raises one
    /// `srtcp_checkpoint_due` event to the client that took the last checkpoint per crossing.
    /// Returns how many unheld counters were dropped.
    pub fn sweep_srtcp_ledger(&self) -> usize {
        let ledger = self.conference.srtcp_ledger();
        let due = ledger.take_due();
        if due > 0 {
            let sink = ledger
                .owner()
                .and_then(|owner| self.event_sink(super::ClientId(owner)));
            match sink {
                Some(sink) => {
                    let _ = sink.try_send(Event::SrtcpCheckpointDue {
                        entries: u32::try_from(due).unwrap_or(u32::MAX),
                    });
                }
                None => tracing::warn!(
                    target: "siphon_rtp::media",
                    keys = due,
                    "SRTCP keys are half way to their send lease and no client is listening for the checkpoint-due event"
                ),
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        ledger.sweep(now)
    }

    /// Seed the ledger from a checkpoint ([`siphon_rtp_proto::Command::RestoreSrtcpIndices`]), each
    /// counter [`SEND_INDEX_MARGIN`] past the index it carries. A blob this very process exported
    /// (a controller that reconnects and restores its stored blob), or one already restored here,
    /// changes nothing and answers a plain ok (the info log says so); a blob of another process gates only the keys it lists and the keys installed afterwards.
    pub(super) fn restore_srtcp_indices(&self, snapshot: &str) -> CmdResult {
        let checkpoint = match decode(snapshot) {
            Ok(checkpoint) => checkpoint,
            Err(reason) => return error_result("restore_srtcp_indices", &reason),
        };
        let imported = match self
            .conference
            .srtcp_ledger()
            .import(&checkpoint, SEND_INDEX_MARGIN)
        {
            Ok(imported) => imported,
            Err(refused) => return error_result("restore_srtcp_indices", &refused),
        };
        if imported.skipped {
            tracing::info!(
                target: "siphon_rtp::media",
                "SRTCP send-index ledger: same engine, nothing to restore (the checkpoint was exported by this engine, or was already restored here; its counters are at or above it)"
            );
            return super::ok_empty();
        }
        tracing::info!(
            target: "siphon_rtp::media",
            keys = imported.applied,
            margin = SEND_INDEX_MARGIN,
            "SRTCP send-index ledger restored from a checkpoint"
        );
        super::ok_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn a_blob_round_trips_and_names_no_key_bytes() {
        let entries = vec![
            LedgerEntry {
                fingerprint: [0xAB; FINGERPRINT_LEN],
                next_index: 7,
            },
            LedgerEntry {
                fingerprint: [0x01; FINGERPRINT_LEN],
                next_index: 2_000_000_000,
            },
        ];
        let checkpoint = LedgerCheckpoint {
            entries,
            generation: "00000000000000ab-4".to_string(),
            unlisted_ceiling: 65_536,
            origin_tag: Some([0x5C; ORIGIN_TAG_LEN]),
        };
        let text = encode(&checkpoint).unwrap();
        assert_eq!(decode(&text).unwrap(), checkpoint);
        assert!(
            text.contains("\"version\":2")
                && text.contains(&"5c".repeat(20))
                && text.contains("\"unlisted_ceiling\":65536")
        );
    }

    #[test]
    fn a_blob_that_is_not_one_is_refused_whole() {
        assert!(decode("not json").is_err());
        assert!(
            decode(r#"{"version":3,"generation":"x-1","unlisted_ceiling":0,"entries":[]}"#)
                .unwrap_err()
                .contains("version 3")
        );
        let short = r#"{"version":1,"generation":"x-1","unlisted_ceiling":0,"entries":[{"fingerprint":"abcd","next_index":1}]}"#;
        assert!(decode(short).unwrap_err().contains("20 octets"));
        let odd = r#"{"version":1,"generation":"x-1","unlisted_ceiling":0,"entries":[{"fingerprint":"zz","next_index":1}]}"#;
        assert!(decode(odd).is_err());
        let bad_tag = r#"{"version":2,"generation":"x-1","unlisted_ceiling":0,"entries":[],"origin_tag":"abcd"}"#;
        assert!(decode(bad_tag).unwrap_err().contains("origin tag"));
        // A blob without the ceiling is one this engine cannot seed unknown keys from: refused.
        assert!(decode(r#"{"version":1,"entries":[]}"#).is_err());
    }

    #[test]
    fn a_version_one_blob_is_read_with_no_origin_tag_even_if_it_carries_one() {
        let text = format!(
            r#"{{"version":1,"generation":"x-1","unlisted_ceiling":0,"entries":[],"origin_tag":"{}"}}"#,
            "ab".repeat(20)
        );
        assert_eq!(decode(&text).unwrap().origin_tag, None);
    }

    #[test]
    fn non_ascii_odd_or_malformed_hex_in_a_blob_is_an_error_never_a_panic() {
        let tag_of = |tag: &str| {
            format!(
                r#"{{"version":2,"generation":"x-1","unlisted_ceiling":0,"entries":[],"origin_tag":"{tag}"}}"#
            )
        };
        let fingerprint_of = |fingerprint: &str| {
            format!(
                r#"{{"version":2,"generation":"x-1","unlisted_ceiling":0,"entries":[{{"fingerprint":"{fingerprint}","next_index":1}}]}}"#
            )
        };
        let forty_ascii = "ab".repeat(20);
        assert!(decode(&tag_of(&forty_ascii)).is_ok(), "the control case");
        assert!(
            decode(&fingerprint_of(&forty_ascii)).is_ok(),
            "the control case"
        );
        for hostile in [
            "\u{1F4A3}",
            "\u{1F4A3}\u{1F4A3}\u{1F4A3}\u{1F4A3}\u{1F4A3}",
            "+f+f+f+f+f+f+f+f+f+f+f+f+f+f+f+f+f+f+f+f",
            "ABCDEFGHIJKLMNOPQRST",
            "abc",
            "\u{e9}b",
            "",
        ] {
            assert!(decode(&tag_of(hostile)).is_err(), "tag {hostile:?}");
            assert!(
                decode(&fingerprint_of(hostile)).is_err(),
                "fingerprint {hostile:?}"
            );
        }
        // Mixed case is fine.
        let mixed = "aB".repeat(20);
        assert!(decode(&tag_of(&mixed)).is_ok());
    }
}
