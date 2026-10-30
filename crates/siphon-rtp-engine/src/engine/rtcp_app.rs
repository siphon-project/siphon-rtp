//! `send_rtcp_app`: one RTCP APP packet (RFC 3550 §6.7), such as a 3GPP TS 24.380 floor control
//! message, from the controller to one party or to the seats of a forwarding room.
//!
//! The received direction is not here: APP packets are read where the stream is terminated (the
//! forwarding room's seat ingress, [`crate::forward`]) and raised as `rtcp_app` events.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, RtcpAppStream};

use crate::forward::{AppRequest, AppTarget};

use super::{error_result, ok_empty, Engine};

/// What a `send_rtcp_app` command carries, after the wire's own shape is out of the way.
pub(super) struct AppSend {
    pub(super) call_id: Option<String>,
    pub(super) conference_id: Option<String>,
    pub(super) from_tag: Option<String>,
    pub(super) except_from_tags: Vec<String>,
    pub(super) stream: RtcpAppStream,
    pub(super) ssrc: Option<u32>,
    pub(super) name: String,
    pub(super) subtype: u8,
    pub(super) payload: Vec<u8>,
}

impl AppSend {
    /// Check the request's shape and build the packet description, before any state is read.
    fn validate(&self) -> Result<AppRequest, String> {
        let name: [u8; 4] = match self.name.as_bytes().try_into() {
            Ok(name) if self.name.is_ascii() => name,
            _ => {
                return Err(format!(
                    "name must be exactly four ASCII characters, got {:?}",
                    self.name
                ))
            }
        };
        if self.subtype > 0x1F {
            return Err(format!(
                "subtype {} does not fit in 5 bits (0..=31)",
                self.subtype
            ));
        }
        if !self.payload.len().is_multiple_of(4) {
            return Err(format!(
                "payload is {} bytes; RTCP APP data must be a multiple of 4",
                self.payload.len()
            ));
        }
        if !self.except_from_tags.is_empty()
            && (self.conference_id.is_none() || self.from_tag.is_some())
        {
            return Err(
                "except_from_tags only applies to a room-wide send (conference_id without from_tag)"
                    .to_string(),
            );
        }
        Ok(AppRequest {
            stream: self.stream,
            ssrc: self.ssrc,
            name,
            subtype: self.subtype,
            payload: self.payload.clone(),
        })
    }
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Send an RTCP APP packet ([`siphon_rtp_proto::Command::SendRtcpApp`]). `ok` only after the
    /// datapath has taken the datagram for every addressed party.
    pub(super) async fn send_rtcp_app(&self, send: AppSend) -> CmdResult {
        let request = match send.validate() {
            Ok(request) => request,
            Err(reason) => return error_result("send_rtcp_app", &reason),
        };
        match (&send.call_id, &send.conference_id) {
            (Some(_), Some(_)) => error_result(
                "send_rtcp_app",
                &"name either call_id or conference_id, not both",
            ),
            (None, None) => error_result("send_rtcp_app", &"name a call_id or a conference_id"),
            (Some(_), None) => error_result(
                "send_rtcp_app",
                &"RTCP APP on a two-party call is not available in this build",
            ),
            (None, Some(room_id)) => {
                let target = match &send.from_tag {
                    Some(tag) => AppTarget::Seat(tag.clone()),
                    None => AppTarget::Room {
                        except: send.except_from_tags.clone(),
                    },
                };
                let forward = self.conference.forward();
                if !forward.contains(room_id) {
                    let reason = if self.conference.contains(room_id) {
                        format!(
                            "{room_id} is a mixing conference; RTCP APP is for forwarding rooms"
                        )
                    } else {
                        format!("unknown forwarding room: {room_id}")
                    };
                    return error_result("send_rtcp_app", &reason);
                }
                match forward.send_app(room_id, target, request).await {
                    Ok(()) => ok_empty(),
                    Err(refusal) => error_result("send_rtcp_app", &refusal),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(name: &str, subtype: u8, payload: Vec<u8>) -> AppSend {
        AppSend {
            call_id: None,
            conference_id: Some("room".into()),
            from_tag: None,
            except_from_tags: Vec::new(),
            stream: RtcpAppStream::Floor,
            ssrc: None,
            name: name.into(),
            subtype,
            payload,
        }
    }

    #[test]
    fn accepts_a_well_formed_floor_message() {
        let request = send("MCPT", 17, vec![0; 12]).validate();
        assert_eq!(request.map(|request| request.name), Ok(*b"MCPT"));
    }

    #[test]
    fn refuses_a_name_that_is_not_four_ascii_characters() {
        for name in ["MCP", "MCPTT", "MCP\u{e9}", ""] {
            assert!(send(name, 0, Vec::new()).validate().is_err(), "{name:?}");
        }
    }

    #[test]
    fn refuses_an_oversized_subtype_and_an_unaligned_payload() {
        assert!(send("MCPT", 32, Vec::new()).validate().is_err());
        assert!(send("MCPT", 31, Vec::new()).validate().is_ok());
        assert!(send("MCPT", 0, vec![0; 3]).validate().is_err());
    }

    #[test]
    fn except_from_tags_only_fits_a_room_wide_send() {
        let mut request = send("MCPT", 0, Vec::new());
        request.except_from_tags = vec!["a".into()];
        assert!(request.validate().is_ok());
        request.from_tag = Some("b".into());
        assert!(request.validate().is_err());
        request.from_tag = None;
        request.conference_id = None;
        request.call_id = Some("call".into());
        assert!(request.validate().is_err());
    }
}
