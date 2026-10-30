//! `send_rtcp_app`: one RTCP APP packet (RFC 3550 §6.7), such as a 3GPP TS 24.380 floor control
//! message, from the controller to one party or to the seats of a forwarding room.
//!
//! The received direction is not here: APP packets are read where the stream is terminated (the
//! forwarding room's seat ingress, [`crate::forward`]) and raised as `rtcp_app` events.

use siphon_rtp_datapath::Datapath;
use siphon_rtp_proto::{CmdResult, RtcpAppStream};

use crate::forward::{AppRequest, AppTarget};

use super::negotiate::apply_received_from;
use super::{error_result, ok_empty, ClientId, Engine};

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

/// The leg of a two-party call a `send_rtcp_app` names, as far as an audio-stream send needs it.
struct CallLegTarget {
    leg: super::Leg,
    secure: bool,
    received_from: Option<std::net::IpAddr>,
}

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Send an RTCP APP packet ([`siphon_rtp_proto::Command::SendRtcpApp`]). `ok` only after the
    /// datapath has taken the datagram for every addressed party.
    pub(super) async fn send_rtcp_app(&self, client: ClientId, send: AppSend) -> CmdResult {
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
            (Some(call_id), None) => {
                let Some(tag) = &send.from_tag else {
                    return error_result(
                        "send_rtcp_app",
                        &"a call needs from_tag, the leg the packet goes to",
                    );
                };
                self.send_call_app(client, call_id, tag, request, send.stream)
                    .await
            }
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

impl<D: Datapath + Clone + Send + 'static> Engine<D> {
    /// Send an APP packet to the leg `tag` of a two-party call ([`siphon_rtp_proto::Command::SendRtcpApp`]
    /// with `call_id`). The floor stream goes through the call's floor leg
    /// ([`crate::call_floor`]); the audio stream goes out of the leg's own RTCP endpoint (its RTP
    /// endpoint under rtcp-mux) to the leg's signalled RTCP address, tightened to its `received_from`
    /// hint.
    ///
    /// The audio stream is served for a plain leg only. On a secure leg the keys live in the
    /// pipeline that terminates it, and an unprotected APP packet there would be dropped by the peer
    /// at best, so the send is refused. It also aims at the signalled address, not at an address the
    /// media path has since latched, which only differs behind a NAT that rewrote it.
    async fn send_call_app(
        &self,
        client: ClientId,
        call_id: &str,
        tag: &str,
        request: AppRequest,
        stream: RtcpAppStream,
    ) -> CmdResult {
        let Some(known) = self.owned_call(client, call_id, |call| {
            let target = if call.from_tag == tag {
                CallLegTarget {
                    leg: call.near,
                    secure: call.near_secure,
                    received_from: call.offer_received_from,
                }
            } else if call.to_tag.as_deref() == Some(tag) {
                let far = call.far?;
                CallLegTarget {
                    leg: far,
                    secure: call.far_local_crypto.is_some() || call.far_dtls,
                    received_from: call.far_received_from,
                }
            } else {
                return None;
            };
            Some(target)
        }) else {
            return super::unknown_call(call_id);
        };
        let Some(target) = known else {
            return error_result("send_rtcp_app", &format!("call {call_id} has no leg {tag}"));
        };
        match stream {
            RtcpAppStream::Floor => {
                // A DTLS leg whose party opened the `mcptt-floor` data channel (a browser).
                if target.leg.floor.is_none() {
                    if let Some(channel) = self
                        .call_floor_channels
                        .get(&(call_id.to_string(), tag.to_string()))
                        .map(|entry| entry.value().clone())
                    {
                        return match crate::floor_channel::send_floor_message(
                            &channel.handle,
                            request.ssrc.unwrap_or(channel.ssrc),
                            request.name,
                            request.subtype,
                            &request.payload,
                        )
                        .await
                        {
                            Ok(()) => ok_empty(),
                            Err(error) => error_result(
                                "send_rtcp_app",
                                &format!("{tag} ({error}) on call {call_id}"),
                            ),
                        };
                    }
                }
                if target.leg.floor.is_none() {
                    return error_result(
                        "send_rtcp_app",
                        &format!("{tag} (no floor stream) on call {call_id}"),
                    );
                }
                match self.conference.floors().send(call_id, tag, request).await {
                    Ok(()) => ok_empty(),
                    Err(error) => error_result("send_rtcp_app", &error),
                }
            }
            RtcpAppStream::Audio => {
                self.send_call_audio_app(call_id, tag, &target, &request)
                    .await
            }
        }
    }

    async fn send_call_audio_app(
        &self,
        call_id: &str,
        tag: &str,
        target: &CallLegTarget,
        request: &AppRequest,
    ) -> CmdResult {
        if target.secure {
            return error_result(
                "send_rtcp_app",
                &format!("{tag} (audio stream of a secure leg is not available) on call {call_id}"),
            );
        }
        // RFC 5761: under rtcp-mux RTCP rides the RTP port; otherwise it has its own endpoint.
        let (endpoint, signalled) = match (target.leg.rtcp, target.leg.remote_rtcp) {
            (Some(rtcp), Some(remote)) => (rtcp, remote),
            _ => match target.leg.remote_rtp {
                Some(remote) => (target.leg.rtp, remote),
                None => {
                    return error_result(
                        "send_rtcp_app",
                        &format!("{tag} (no destination known yet) on call {call_id}"),
                    )
                }
            },
        };
        let destination =
            apply_received_from(Some(signalled), target.received_from).unwrap_or(signalled);
        // A relayed audio stream has no SSRC of the engine's own (the relay keeps the far party's), so
        // there is nothing to default to: the controller names the one the receiving party expects.
        let Some(ssrc) = request.ssrc else {
            return error_result(
                "send_rtcp_app",
                &format!("{tag}: the audio stream of a two-party call needs an explicit ssrc"),
            );
        };
        let mut buffer = vec![0u8; crate::app_events::MAX_APP_DATAGRAM];
        let length = match siphon_rtp_media::rtcp::write_app(
            request.subtype,
            ssrc,
            request.name,
            &request.payload,
            &mut buffer,
        ) {
            Ok(length) => length,
            Err(error) => return error_result("send_rtcp_app", &error),
        };
        match self
            .datapath
            .send(endpoint.id, destination, &buffer[..length])
            .await
        {
            Ok(_) => ok_empty(),
            Err(error) => error_result(
                "send_rtcp_app",
                &format!("{tag} (send failed: {error}) on call {call_id}"),
            ),
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
