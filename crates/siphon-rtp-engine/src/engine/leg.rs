//! Constructors of [`Leg`], the engine's record of one party of a call.

use siphon_rtp_datapath::Endpoint;

use super::Leg;

impl Leg {
    /// A leg with only its audio endpoints and advertised address: no signalled remote, and no text,
    /// fax or floor stream. Struct-update base for the legs that add some of those.
    pub(super) fn audio_only(
        rtp: Endpoint,
        rtcp: Option<Endpoint>,
        advertised_ip: std::net::IpAddr,
    ) -> Self {
        Self {
            rtp,
            rtcp,
            remote_rtp: None,
            remote_rtcp: None,
            advertised_ip,
            text: None,
            text_remote_rtp: None,
            image: None,
            image_remote: None,
            floor: None,
            floor_remote: None,
            floor_format: siphon_rtp_proto::ControlFormat::Mcptt,
        }
    }
}
