//! The decoded copy a **relay-only** direction keeps for its sinks, and the attachments an actor
//! rebuild carries across.
//!
//! A plain relay held in userspace for a WS tee or a decoded recording forwards every packet exactly
//! as it arrived. The sinks get their PCM from a decode of a copy, run after the forward, so a frame
//! the decoder rejects costs the sinks that frame and never the call.

use siphon_rtp_codec::factory::CodecSpec;
use siphon_rtp_codec::Decoder;
use siphon_rtp_media::fanout::MediaSink;
use siphon_rtp_media::rtp::RtpPacket;

use super::{Direction, LegMeta, MediaCall, PcapCapture, MAX_PCM};
use crate::x3::X3Tap;

/// The side decode of a **relay-only** direction: a decoded copy of the ingress for the sinks that
/// want PCM (a WS tee, a decoded recording), next to a relay that forwards each packet verbatim.
///
/// The decoder is built when the first sink attaches, so a relay promoted only for a SIPREC raw tee,
/// a pcap capture or an X3 tap never runs a codec. A frame it cannot decode costs the sinks that
/// frame (each is told through [`MediaSink::frame_undecodable`]) and never the forwarded packet.
pub(super) struct TapDecode {
    pub(super) codec: CodecSpec,
    /// `None` until a sink attaches, and when this build cannot decode the codec (logged once).
    pub(super) decoder: Option<Box<dyn Decoder>>,
    /// Channels the decoder emits, folded to mono before the sinks see the frame.
    channels: u8,
    /// Preallocated decode buffer, [`MAX_PCM`] long once the decoder exists (empty before).
    scratch: Vec<i16>,
    /// Ingress frames the decoder rejected. The first is logged at `warn!`, the rest at `debug!`.
    pub(super) undecodable: u64,
}

impl TapDecode {
    pub(super) fn new(codec: CodecSpec) -> Self {
        Self {
            codec,
            decoder: None,
            channels: 1,
            scratch: Vec::new(),
            undecodable: 0,
        }
    }

    /// Build the decoder if it is not built yet. A codec this build cannot decode leaves it `None`:
    /// the engine refuses a tee or a recording on such a leg before attaching a sink, so reaching
    /// that here means the sinks get nothing — logged, and the relay is unaffected.
    fn ensure_decoder(&mut self) {
        if self.decoder.is_some() {
            return;
        }
        match siphon_rtp_codec::factory::decoder_for(&self.codec) {
            Ok(decoder) => {
                self.channels = decoder.params().channels.max(1);
                self.decoder = Some(decoder);
                self.scratch = vec![0i16; MAX_PCM];
            }
            Err(error) => tracing::warn!(
                target: "siphon_rtp::media",
                %error,
                codec = %self.codec.encoding_name,
                "relay sink attached to a leg whose codec this build cannot decode; it gets no audio"
            ),
        }
    }
}

/// What a rebuild of a call's media actor carries from the old actor to the new one
/// ([`super::MediaControl::TakeAttachments`]): everything a control verb attached and the engine cannot
/// reconstruct on its own. Indexed `[leg A, leg B]`, by source leg for the ingress forks and the
/// DTMF block and by receiving party for the egress taps. SIPREC raw tees are not here: the engine
/// re-attaches them from its subscriptions.
#[derive(Default)]
pub struct CarriedAttachments {
    pub forks: [Vec<Box<dyn MediaSink>>; 2],
    pub egress_taps: [Vec<Box<dyn MediaSink>>; 2],
    pub x3: Option<(X3Tap, X3Tap)>,
    pub capture: Option<PcapCapture>,
    pub dtmf_blocked: [bool; 2],
}

impl Direction {
    /// Build a relay-only direction's side decoder for a sink about to attach. A no-op on a
    /// transcoding direction, and once the decoder exists.
    pub(super) fn prepare_relay_tap(&mut self) {
        if let Some(tap) = self.tap.as_mut() {
            tap.ensure_decoder();
        }
    }

    /// Decode one forwarded relay-only packet for the direction's sinks: the ingress forks (what
    /// this party said) and the egress taps (what the other party hears, which on a relay is the
    /// same audio). A no-op with no sink attached, for RTCP and for any payload type but the leg's
    /// audio one (telephone-events and comfort noise are not audio to tap).
    ///
    /// A frame the decoder rejects is skipped for the sinks, counted, and reported to each sink as
    /// undecodable (a WS tee counts it in `frames_dropped`). The packet was already forwarded.
    pub(super) fn feed_relay_sinks(&mut self, data: &[u8], leg_meta: LegMeta<'_>) {
        let Self {
            tap,
            forks,
            egress_taps,
            ..
        } = self;
        if forks.is_empty() && egress_taps.is_empty() {
            return;
        }
        let Some(tap) = tap.as_mut() else {
            return;
        };
        let Some(decoder) = tap.decoder.as_mut() else {
            return;
        };
        // RFC 5761 demux: 64..=95 is RTCP, which carries no audio.
        if (64..=95).contains(&(data[1] & 0x7f)) {
            return;
        }
        let Ok(parsed) = RtpPacket::parse(data) else {
            return;
        };
        if parsed.payload_type != tap.codec.payload_type {
            return;
        }
        match decoder.decode(parsed.payload, &mut tap.scratch) {
            Ok(samples) => {
                let samples =
                    siphon_rtp_codec::downmix_to_mono(&mut tap.scratch[..samples], tap.channels);
                let pcm = &tap.scratch[..samples];
                for sink in forks.iter_mut().chain(egress_taps.iter_mut()) {
                    sink.write_pcm(pcm);
                }
            }
            Err(error) => {
                tap.undecodable += 1;
                if tap.undecodable == 1 {
                    tracing::warn!(
                        target: "siphon_rtp::media",
                        call_id = leg_meta.call_id,
                        from_tag = leg_meta.near_tag,
                        %error,
                        payload_type = parsed.payload_type,
                        payload_len = parsed.payload.len(),
                        ssrc = parsed.ssrc,
                        "relayed frame could not be decoded for the call's tee or recording; the \
                         packet was forwarded (further failures at debug)"
                    );
                } else {
                    tracing::debug!(
                        target: "siphon_rtp::media",
                        call_id = leg_meta.call_id,
                        %error,
                        payload_type = parsed.payload_type,
                        payload_len = parsed.payload.len(),
                        undecodable = tap.undecodable,
                        "relayed frame could not be decoded for the call's tee or recording"
                    );
                }
                for sink in forks.iter_mut().chain(egress_taps.iter_mut()) {
                    sink.frame_undecodable();
                }
            }
        }
    }
}

impl MediaCall {
    /// Move out everything attached to this call ([`super::MediaControl::TakeAttachments`]), leaving it
    /// a bare relay or transcode.
    pub fn take_attachments(&mut self) -> CarriedAttachments {
        let x3 = match (self.a_to_b.x3.take(), self.b_to_a.x3.take()) {
            (Some(leg_a), Some(leg_b)) => Some((leg_a, leg_b)),
            _ => None,
        };
        CarriedAttachments {
            forks: [
                std::mem::take(&mut self.a_to_b.forks),
                std::mem::take(&mut self.b_to_a.forks),
            ],
            // `toward_a` is the direction whose egress faces A: `b_to_a`.
            egress_taps: [
                std::mem::take(&mut self.b_to_a.egress_taps),
                std::mem::take(&mut self.a_to_b.egress_taps),
            ],
            x3,
            capture: self.capture.take(),
            dtmf_blocked: [self.a_to_b.dtmf_blocked, self.b_to_a.dtmf_blocked],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_decoder_is_built_only_when_a_sink_asks_for_it() {
        let mut tap = TapDecode::new(CodecSpec::new(8, "PCMA", 8000, 1, 20));
        assert!(tap.decoder.is_none());
        assert!(tap.scratch.is_empty(), "no buffer before a sink");
        tap.ensure_decoder();
        assert!(tap.decoder.is_some());
        assert_eq!(tap.scratch.len(), MAX_PCM);
        assert_eq!(tap.channels, 1);
    }

    #[test]
    fn a_codec_this_build_cannot_decode_leaves_the_sinks_without_audio() {
        let mut tap = TapDecode::new(CodecSpec::new(99, "X-NOT-A-CODEC", 8000, 1, 20));
        tap.ensure_decoder();
        assert!(tap.decoder.is_none());
        assert!(tap.scratch.is_empty());
    }
}
