//! The per-leg media pipeline: the composable bridge between RTP on the wire and linear PCM.
//!
//! Ingress: RTP bytes → depacketize → [`JitterBuffer`] → decode (or `conceal` on a gap) → PCM.
//! Egress: PCM → encode → packetize → RTP bytes, with the leg owning the outgoing sequence /
//! timestamp / SSRC. This is the tap point the WS bridge, recorder, and mixer all read PCM from
//! and write PCM to; it is synchronous and allocation-light so it unit-tests without sockets.

use bytes::Bytes;
use siphon_rtp_codec::{CodecError, Decoder, Encoder};

use crate::jitter::{JitterBuffer, JitterOutput, PushResult};
use crate::rtp::{write_packet, RtpError, RtpHeader, RtpPacket};

/// Largest codec payload the egress buffer accommodates (AMR-WB 23.85k ≈ 60 B; G.711 ≤ 160 B).
const MAX_PAYLOAD: usize = 1500;

/// Errors from the leg pipeline.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LegError {
    /// The ingress RTP packet did not parse.
    #[error("rtp: {0}")]
    Rtp(#[from] RtpError),
    /// The codec rejected the frame.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
}

/// What [`MediaLeg::next_pcm`] produced for this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcmFrame {
    /// A frame decoded from a received packet, of this many samples.
    Decoded(usize),
    /// A concealment frame synthesized for a lost packet, of this many samples.
    Concealed(usize),
    /// The jitter buffer had nothing to play this tick.
    Starved,
}

/// A bidirectional media leg: jitter-buffered decode on ingress, packetized encode on egress.
pub struct MediaLeg {
    decoder: Box<dyn Decoder>,
    encoder: Box<dyn Encoder>,
    jitter: JitterBuffer,
    egress_sequence: u16,
    egress_timestamp: u32,
    egress_ssrc: u32,
    egress_payload_type: u8,
    frame_samples: usize,
    /// Egress RTP timestamp step per packet, in **RTP-clock** units. Equals the egress codec frame
    /// size for every codec whose RTP clock matches its sample rate, but not for G.722 (16 kHz audio
    /// clocked at 8 kHz, RFC 3551 §4.5.2 — there it is half the sample count).
    egress_timestamp_increment: u32,
    /// Total packets emitted on this leg's egress stream (RTCP SR sender packet count, RFC 3550 §6.4.1).
    egress_packets: u32,
    /// Total payload octets emitted (RTCP SR sender octet count — excludes RTP header/padding).
    egress_octets: u32,
}

impl MediaLeg {
    /// Build a leg from a decoder/encoder pair and a primed jitter buffer. `egress_ssrc` and
    /// `egress_payload_type` stamp packets the leg emits; the timestamp advances by one egress codec
    /// frame (at the codec's RTP clock) per emitted packet.
    pub fn new(
        decoder: Box<dyn Decoder>,
        encoder: Box<dyn Encoder>,
        jitter: JitterBuffer,
        egress_ssrc: u32,
        egress_payload_type: u8,
    ) -> Self {
        let frame_samples = decoder.frame_samples();
        // RFC 3551 §4.5.2: the egress RTP timestamp advances at the codec's RTP clock, which is not
        // always its sample rate (G.722 clocks RTP at 8 kHz while sampling 16 kHz). Derive the step
        // from the encoder so a G.722 leg advances 160 — not 320 — per 20 ms packet.
        let egress_params = encoder.params();
        let egress_rate = egress_params.sample_rate_hz;
        let egress_frame_samples = encoder.frame_samples() as u32;
        let egress_timestamp_increment = if egress_rate == 0 {
            egress_frame_samples
        } else {
            ((u64::from(egress_frame_samples) * u64::from(encoder.rtp_clock_rate_hz()))
                / u64::from(egress_rate)) as u32
        };
        Self {
            decoder,
            encoder,
            jitter,
            egress_sequence: 0,
            egress_timestamp: 0,
            egress_ssrc,
            egress_payload_type,
            frame_samples,
            egress_timestamp_increment,
            egress_packets: 0,
            egress_octets: 0,
        }
    }

    /// Samples in one nominal codec frame at the native rate.
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    /// Depacketize an inbound RTP packet and buffer its payload for playout.
    pub fn ingest_rtp(&mut self, packet: &[u8]) -> Result<PushResult, LegError> {
        let parsed = RtpPacket::parse(packet)?;
        Ok(self
            .jitter
            .push(parsed.sequence, Bytes::copy_from_slice(parsed.payload)))
    }

    /// Produce the next PCM frame for playout: decode a buffered packet, conceal a gap, or report
    /// starvation. `out` must hold at least [`MediaLeg::frame_samples`] samples.
    pub fn next_pcm(&mut self, out: &mut [i16]) -> Result<PcmFrame, LegError> {
        match self.jitter.pop() {
            JitterOutput::Packet(payload) => {
                let written = self.decoder.decode(&payload, out)?;
                Ok(PcmFrame::Decoded(written))
            }
            JitterOutput::Conceal => {
                let written = self.decoder.conceal(out)?;
                Ok(PcmFrame::Concealed(written))
            }
            JitterOutput::Starved => Ok(PcmFrame::Starved),
        }
    }

    /// Encode and packetize one PCM frame into `out`, returning the RTP packet length. The egress
    /// sequence advances by one and the timestamp by one codec frame.
    pub fn encode_rtp(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, LegError> {
        let mut payload = [0u8; MAX_PAYLOAD];
        let payload_len = self.encode_payload(pcm, &mut payload)?;
        self.packetize(&payload[..payload_len], false, out)
    }

    /// Encode one PCM frame into a bare codec payload (no RTP framing, no counter advance), returning
    /// the payload length. This is the **shared-encode** primitive the conference mixer uses: encode
    /// the one shared listener mix a single time, then [`MediaLeg::packetize`] that payload into each
    /// listener leg's own RTP stream — one encode, N sends.
    pub fn encode_payload(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, LegError> {
        self.encoder.encode(pcm, out).map_err(LegError::from)
    }

    /// Frame a pre-encoded codec payload into an RTP packet stamped with **this leg's own**
    /// sequence / timestamp / SSRC (RFC 3550 §5.1), advancing both counters by one packet / one codec
    /// frame. `marker` sets the marker bit — the conference sets it on the first egress packet of a
    /// talkspurt, false in steady state. Returns the packet length.
    pub fn packetize(
        &mut self,
        payload: &[u8],
        marker: bool,
        out: &mut [u8],
    ) -> Result<usize, LegError> {
        let header = RtpHeader {
            marker,
            payload_type: self.egress_payload_type,
            sequence: self.egress_sequence,
            timestamp: self.egress_timestamp,
            ssrc: self.egress_ssrc,
        };
        let total = write_packet(&header, payload, out)?;
        self.egress_sequence = self.egress_sequence.wrapping_add(1);
        self.egress_timestamp = self
            .egress_timestamp
            .wrapping_add(self.egress_timestamp_increment);
        self.egress_packets = self.egress_packets.wrapping_add(1);
        self.egress_octets = self.egress_octets.wrapping_add(payload.len() as u32);
        Ok(total)
    }

    /// The current egress RTP timestamp (the value the next packet will carry) — the RTCP SR's RTP
    /// timestamp field, mapped to the SR's NTP wall-clock time (RFC 3550 §6.4.1).
    #[must_use]
    pub fn egress_timestamp(&self) -> u32 {
        self.egress_timestamp
    }

    /// Total packets emitted on this leg's egress stream (RTCP SR sender packet count).
    #[must_use]
    pub fn egress_packets(&self) -> u32 {
        self.egress_packets
    }

    /// Total payload octets emitted on this leg's egress stream (RTCP SR sender octet count).
    #[must_use]
    pub fn egress_octets(&self) -> u32 {
        self.egress_octets
    }

    /// The synthesized egress SSRC stamped on this leg's outgoing packets (RFC 3550 §5.1). Each
    /// conference participant carries a distinct SSRC even when several share one shared-encode payload.
    #[must_use]
    pub fn egress_ssrc(&self) -> u32 {
        self.egress_ssrc
    }

    /// Jitter-buffer counters for this leg.
    #[must_use]
    pub fn jitter_stats(&self) -> crate::jitter::JitterStats {
        self.jitter.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_codec::g711::G711;

    /// A G.711 µ-law leg with a shallow jitter buffer (target depth 1 for tight test control).
    fn ulaw_leg() -> MediaLeg {
        MediaLeg::new(
            Box::new(G711::ulaw()),
            Box::new(G711::ulaw()),
            JitterBuffer::new(1, 16),
            0xABCD_1234,
            0,
        )
    }

    /// Build a G.711 RTP packet with the given sequence and 160-byte payload.
    fn ulaw_packet(sequence: u16, payload_byte: u8) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 0x1111_2222,
        };
        let payload = [payload_byte; 160];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn decodes_ingested_rtp_to_pcm() {
        let mut leg = ulaw_leg();
        leg.ingest_rtp(&ulaw_packet(0, 0xFF)).expect("ingest");
        let mut pcm = [0i16; 160];
        let frame = leg.next_pcm(&mut pcm).expect("decode");
        assert_eq!(frame, PcmFrame::Decoded(160));
        // µ-law 0xFF decodes to 0.
        assert!(pcm.iter().all(|&sample| sample == 0));
    }

    #[test]
    fn conceals_a_lost_packet_then_resumes() {
        let mut leg = ulaw_leg();
        leg.ingest_rtp(&ulaw_packet(0, 0xFF)).expect("ingest 0");
        leg.ingest_rtp(&ulaw_packet(2, 0xFF)).expect("ingest 2"); // seq 1 lost
        let mut pcm = [0i16; 160];
        assert_eq!(leg.next_pcm(&mut pcm).expect("p0"), PcmFrame::Decoded(160));
        assert_eq!(leg.next_pcm(&mut pcm).expect("conceal"), PcmFrame::Concealed(160));
        assert_eq!(leg.next_pcm(&mut pcm).expect("p2"), PcmFrame::Decoded(160));
        assert_eq!(leg.jitter_stats().losses, 1);
    }

    #[test]
    fn starves_when_empty() {
        let mut leg = ulaw_leg();
        let mut pcm = [0i16; 160];
        assert_eq!(leg.next_pcm(&mut pcm).expect("starve"), PcmFrame::Starved);
    }

    #[test]
    fn egress_advances_sequence_and_timestamp() {
        let mut leg = ulaw_leg();
        let pcm = [1234i16; 160];
        let mut out = [0u8; 200];

        let len0 = leg.encode_rtp(&pcm, &mut out).expect("encode 0");
        let packet0 = RtpPacket::parse(&out[..len0]).expect("parse 0");
        assert_eq!(packet0.sequence, 0);
        assert_eq!(packet0.timestamp, 0);
        assert_eq!(packet0.ssrc, 0xABCD_1234);
        assert_eq!(packet0.payload.len(), 160);

        let len1 = leg.encode_rtp(&pcm, &mut out).expect("encode 1");
        let packet1 = RtpPacket::parse(&out[..len1]).expect("parse 1");
        assert_eq!(packet1.sequence, 1);
        assert_eq!(packet1.timestamp, 160, "timestamp advances one codec frame");
    }

    #[test]
    fn encode_then_decode_roundtrips_through_g711() {
        // PCM → encode → RTP → ingest → decode → PCM should match G.711's lossy round-trip.
        let mut sender = ulaw_leg();
        let pcm_in: Vec<i16> = (0..160).map(|index| ((index * 37) as i16) << 6).collect();
        let mut rtp = [0u8; 200];
        let len = sender.encode_rtp(&pcm_in, &mut rtp).expect("encode");

        let mut receiver = ulaw_leg();
        receiver.ingest_rtp(&rtp[..len]).expect("ingest");
        let mut pcm_out = [0i16; 160];
        assert_eq!(receiver.next_pcm(&mut pcm_out).expect("decode"), PcmFrame::Decoded(160));

        // Direct G.711 reference round-trip for comparison.
        let mut direct = G711::ulaw();
        let mut payload = [0u8; 160];
        let mut reference = [0i16; 160];
        use siphon_rtp_codec::{Decoder as _, Encoder as _};
        direct.encode(&pcm_in, &mut payload).expect("ref encode");
        direct.decode(&payload, &mut reference).expect("ref decode");
        assert_eq!(pcm_out, reference);
    }

    #[test]
    fn shared_encode_payload_fans_out_to_distinct_streams() {
        // The conference shared-encode path: encode the listener mix once, then packetize the SAME
        // payload into two legs that each stamp their own SSRC / sequence. The bytes on the wire
        // share a payload but are distinct RTP streams (RFC 3550 §5.1).
        let mut source = ulaw_leg();
        let pcm = [4321i16; 160];
        let mut payload = [0u8; 200];
        let payload_len = source.encode_payload(&pcm, &mut payload).expect("encode once");

        let mut leg_a = MediaLeg::new(
            Box::new(G711::ulaw()),
            Box::new(G711::ulaw()),
            JitterBuffer::new(1, 16),
            0x1111_1111,
            0,
        );
        let mut leg_b = MediaLeg::new(
            Box::new(G711::ulaw()),
            Box::new(G711::ulaw()),
            JitterBuffer::new(1, 16),
            0x2222_2222,
            0,
        );

        let mut out_a = [0u8; 200];
        let mut out_b = [0u8; 200];
        let len_a = leg_a
            .packetize(&payload[..payload_len], true, &mut out_a)
            .expect("packetize a");
        let len_b = leg_b
            .packetize(&payload[..payload_len], false, &mut out_b)
            .expect("packetize b");

        let packet_a = RtpPacket::parse(&out_a[..len_a]).expect("parse a");
        let packet_b = RtpPacket::parse(&out_b[..len_b]).expect("parse b");
        assert_eq!(packet_a.payload, packet_b.payload, "one encode, shared payload");
        assert_eq!(packet_a.ssrc, 0x1111_1111);
        assert_eq!(packet_b.ssrc, 0x2222_2222);
        assert_ne!(packet_a.ssrc, packet_b.ssrc, "distinct egress streams");
    }

    #[test]
    fn encode_rtp_matches_encode_payload_then_packetize() {
        // encode_rtp is exactly encode_payload + packetize(marker = false): the split must not change
        // the bytes the existing 2-party callers produce.
        let mut split = ulaw_leg();
        let mut combined = ulaw_leg();
        let pcm = [777i16; 160];

        let mut payload = [0u8; 200];
        let mut via_split = [0u8; 200];
        let payload_len = split.encode_payload(&pcm, &mut payload).expect("encode");
        let split_len = split
            .packetize(&payload[..payload_len], false, &mut via_split)
            .expect("packetize");

        let mut via_combined = [0u8; 200];
        let combined_len = combined.encode_rtp(&pcm, &mut via_combined).expect("encode_rtp");

        assert_eq!(&via_split[..split_len], &via_combined[..combined_len]);
        assert_eq!(split.egress_ssrc(), combined.egress_ssrc());
    }
}
