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
use siphon_rtp_srtp::srtcp_gcm::FINGERPRINT_LEN;

use crate::ha;
use crate::srtcp_ledger::{LedgerCheckpoint, LedgerEntry};

use super::snapshot_floor::SEND_INDEX_MARGIN;
use super::{error_result, Engine};

/// The blob's format version.
const BLOB_VERSION: u32 = 1;

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
    };
    serde_json::to_string(&blob).map_err(|error| error.to_string())
}

/// The entries of `text`, or why it is not a blob this engine reads.
fn decode(text: &str) -> Result<LedgerCheckpoint, String> {
    let blob: Blob = serde_json::from_str(text)
        .map_err(|error| format!("not an SRTCP index ledger: {error}"))?;
    if blob.version != BLOB_VERSION {
        return Err(format!(
            "SRTCP index ledger version {} is not the {BLOB_VERSION} this engine reads",
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
    Ok(LedgerCheckpoint {
        generation: blob.generation,
        entries,
        unlisted_ceiling: blob.unlisted_ceiling,
    })
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Export the SRTCP send-index ledger ([`siphon_rtp_proto::Command::CheckpointSrtcpIndices`]).
    /// Every entry is exported, and from here each counter has a lease a margin past its exported
    /// index; `client` is who the `srtcp_checkpoint_due` events go to.
    pub(super) fn checkpoint_srtcp_indices(&self, client: super::ClientId) -> CmdResult {
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
    /// counter [`SEND_INDEX_MARGIN`] past the index it carries.
    pub(super) fn restore_srtcp_indices(&self, snapshot: &str) -> CmdResult {
        let checkpoint = match decode(snapshot) {
            Ok(checkpoint) => checkpoint,
            Err(reason) => return error_result("restore_srtcp_indices", &reason),
        };
        let applied = match self
            .conference
            .srtcp_ledger()
            .import(&checkpoint, SEND_INDEX_MARGIN)
        {
            Ok(applied) => applied,
            Err(refused) => return error_result("restore_srtcp_indices", &refused),
        };
        tracing::info!(
            target: "siphon_rtp::media",
            keys = applied,
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
        };
        let text = encode(&checkpoint).unwrap();
        assert_eq!(decode(&text).unwrap(), checkpoint);
        assert!(text.contains("\"version\":1") && text.contains("\"unlisted_ceiling\":65536"));
    }

    #[test]
    fn a_blob_that_is_not_one_is_refused_whole() {
        assert!(decode("not json").is_err());
        assert!(
            decode(r#"{"version":2,"generation":"x-1","unlisted_ceiling":0,"entries":[]}"#)
                .unwrap_err()
                .contains("version 2")
        );
        let short = r#"{"version":1,"generation":"x-1","unlisted_ceiling":0,"entries":[{"fingerprint":"abcd","next_index":1}]}"#;
        assert!(decode(short).unwrap_err().contains("20 octets"));
        let odd = r#"{"version":1,"generation":"x-1","unlisted_ceiling":0,"entries":[{"fingerprint":"zz","next_index":1}]}"#;
        assert!(decode(odd).is_err());
        // A blob without the ceiling is one this engine cannot seed unknown keys from: refused.
        assert!(decode(r#"{"version":1,"entries":[]}"#).is_err());
    }
}
