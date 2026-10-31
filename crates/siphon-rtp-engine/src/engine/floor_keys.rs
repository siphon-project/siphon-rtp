//! `set_floor_keys`: replace the SRTCP keys of one floor stream (3GPP TS 33.180 §9.4), on a
//! forwarding-room seat or a leg of a two-party call.
//!
//! The room or call-floor actor that owns the stream applies the keys between two datagrams and the
//! command answers `ok` only after that, so a controller that distributed a key and then sees `ok`
//! knows the very next floor packet in either direction is under it. The set REPLACES the stream's:
//! the newest two are accepted, outbound uses the last, and an unkeyed stream becomes protected.
//! An empty set removes the protection.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, FloorKey};

use super::{error_result, ok_empty, ClientId, Engine};

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Apply [`siphon_rtp_proto::Command::SetFloorKeys`]. A call is visible only to the client that
    /// owns it, exactly as for `send_rtcp_app`.
    pub(super) async fn set_floor_keys(
        &self,
        client: ClientId,
        call_id: Option<String>,
        conference_id: Option<String>,
        from_tag: &str,
        keys: &[FloorKey],
    ) -> CmdResult {
        let master = match crate::floor_srtcp::master_keys(keys) {
            Ok(master) => master,
            Err(reason) => return error_result("set_floor_keys", &reason),
        };
        match (call_id, conference_id) {
            (Some(_), Some(_)) => error_result(
                "set_floor_keys",
                &"name either call_id or conference_id, not both",
            ),
            (None, None) => error_result("set_floor_keys", &"name a call_id or a conference_id"),
            (Some(call_id), None) => {
                if self.owned_call(client, &call_id, |_| ()).is_none() {
                    return super::unknown_call(&call_id);
                }
                match self
                    .conference
                    .floors()
                    .set_keys(&call_id, from_tag, master)
                    .await
                {
                    Ok(()) => ok_empty(),
                    Err(error) => error_result("set_floor_keys", &error),
                }
            }
            (None, Some(room_id)) => {
                match self
                    .conference
                    .forward()
                    .set_floor_keys(&room_id, from_tag, master)
                    .await
                {
                    Ok(()) => ok_empty(),
                    Err(error) => error_result("set_floor_keys", &error),
                }
            }
        }
    }
}
