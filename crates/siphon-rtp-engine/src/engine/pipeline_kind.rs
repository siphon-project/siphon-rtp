//! Media pipeline classification and checkpoint eligibility helpers.

use super::PipelineKind;

impl PipelineKind {
    /// Why this call's media path cannot be replicated to a standby, or `None` when it can.
    ///
    /// The HA snapshot record describes exactly one topology: a two-party call whose **far** (B) side
    /// may be secure. Everything else has state it has nowhere to put — the caller's own keying, a
    /// second secure leg, keys that came from a handshake rather than from SDP. `restore` has always
    /// rejected those, but it rejected them *at failover*, having accepted a `checkpoint` that looked
    /// like it worked; and because a secure **offerer** is recorded as a plain `Srtp` bridge, the
    /// rejection it eventually produced named a kind the call never was. Refusing here instead means
    /// the operator learns at checkpoint time, while they can still act on it, and the reason names
    /// the real obstacle. `restore`'s own checks stay as defence in depth.
    pub(super) fn checkpoint_refusal(self) -> Option<&'static str> {
        match self {
            Self::Passthrough | Self::Srtp | Self::Media | Self::SrtpMedia => None,
            Self::SrtpOfferer | Self::SrtpOffererMedia => Some(
                "a secure caller's own keying is not carried in the snapshot record, so a standby \
                 would resume the call with the caller demoted to plaintext",
            ),
            Self::SrtpTranscrypt | Self::SrtpTranscryptMedia => Some(
                "a secure↔secure (transcrypt) call has two secure legs and the snapshot record \
                 carries one",
            ),
            Self::Dtls | Self::DtlsMedia | Self::DtlsOfferer | Self::DtlsOffererMedia => Some(
                "a DTLS-SRTP call's keys come from the handshake rather than the SDP, so an \
                 established association cannot move to a standby",
            ),
            // Deliberately `None`: a WebSocket takeover has no far leg at all, so `to_snapshot`
            // yields nothing and the single-leg refusal declines it with a more specific reason
            // than this function could give.
            Self::Ws => None,
            Self::Seated => Some(
                "the call's leg is seated in a conference room, whose mixer state the snapshot \
                 record does not carry",
            ),
        }
    }

    /// Whether the call's media runs through a crypto bridge, which relays SRTP without decoding it.
    /// Nothing that needs the decoded audio (a recording, a tee, a SIPREC fork, a DTMF block) has
    /// anything to attach to on such a call.
    pub(super) fn is_crypto_bridge(self) -> bool {
        matches!(
            self,
            Self::Srtp | Self::SrtpOfferer | Self::SrtpTranscrypt | Self::Dtls | Self::DtlsOfferer
        )
    }

    /// Whether the call's media is decoded to PCM and re-encoded on its way through the engine — the
    /// complement of the payload leaving exactly as it arrived. The relay and the crypto bridges
    /// forward the payload verbatim (a bridge re-encrypts, it does not re-encode); the rest run a
    /// [`MediaCall`] actor over decoded samples.
    ///
    /// Used to refuse a call that asked for opaque relay (`fax_passthrough`) and then resolved to a
    /// pipeline that would requantize it.
    pub(super) fn decodes_audio(self) -> bool {
        self.is_transcode() || self == Self::Ws
    }

    /// Whether A↔B runs through a [`MediaCall`] actor that decodes what each party sends and
    /// re-encodes it for the other, so each party is presented its own codec. The one list every
    /// "is this call transcoded" decision reads — three copies of it had drifted, each missing the
    /// secure↔secure kind.
    pub(super) fn is_transcode(self) -> bool {
        matches!(
            self,
            Self::Media
                | Self::SrtpMedia
                | Self::DtlsMedia
                | Self::SrtpTranscryptMedia
                | Self::SrtpOffererMedia
                | Self::DtlsOffererMedia
        )
    }
}
