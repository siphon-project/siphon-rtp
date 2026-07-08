//! The per-leg media pipeline: the composable bridge between RTP on the wire and linear PCM.
//!
//! Ingress: RTP bytes → depacketize → [`JitterBuffer`] → decode (or `conceal` on a gap) → PCM.
//! Egress: PCM → encode → packetize → RTP bytes, with the leg owning the outgoing sequence /
//! timestamp / SSRC. This is the tap point the WS bridge, recorder, and mixer all read PCM from
//! and write PCM to; it is synchronous and allocation-light so it unit-tests without sockets.

use bytes::Bytes;
use siphon_rtp_codec::{CodecError, Decoder, Encoder};

use crate::ingress::IngressStats;
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
    /// Receiver-side reception statistics for this leg's inbound stream (RFC 3550 §6.4.1): SSRC latch,
    /// extended sequence, interarrival jitter, and RTT-from-reception-report. Shared with the
    /// transcode/relay directions ([`crate::ingress::IngressStats`]) so the jitter/RTT logic lives in
    /// one place; the leg overlays its own **jitter-buffer-derived** loss (see
    /// [`MediaLeg::ingress_loss_percent`] / [`MediaLeg::fraction_lost_since_last_report`]).
    ingress: IngressStats,
    /// Middle 32 bits of the NTP timestamp from the most recent inbound Sender Report (the RR's LSR
    /// field, RFC 3550 §6.4.1), or `0` before any SR is seen.
    last_sr_ntp_middle: u32,
    /// Arrival (µs) of the most recent inbound SR, for the RR's DLSR field; `None` before any SR.
    last_sr_arrival_micros: Option<u64>,
    /// Cumulative `expected` at the previous reception report, so `fraction_lost` describes just the
    /// interval since (RFC 3550 §6.4.1 / Appendix A.3). `0` before the first report.
    fraction_lost_expected_prior: u32,
    /// Cumulative `lost` at the previous reception report (the counterpart snapshot to
    /// `fraction_lost_expected_prior`). `0` before the first report.
    fraction_lost_lost_prior: u32,
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
        let ingress_clock_rate_hz = decoder.rtp_clock_rate_hz();
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
            ingress: IngressStats::new(ingress_clock_rate_hz),
            last_sr_ntp_middle: 0,
            last_sr_arrival_micros: None,
            fraction_lost_expected_prior: 0,
            fraction_lost_lost_prior: 0,
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
        // Fold the packet into the receiver statistics (SSRC latch, extended sequence, received
        // count, and the RTP timestamp `observe_arrival` needs) — RFC 3550 §6.4.1 / Appendix A.
        self.ingress
            .on_rtp(parsed.ssrc, parsed.sequence, parsed.timestamp);
        Ok(self
            .jitter
            .push(parsed.sequence, Bytes::copy_from_slice(parsed.payload)))
    }

    /// SSRC of this leg's inbound stream (RFC 3550 §5.1), or `None` before the first packet — the
    /// source the RTCP reception report describes.
    #[must_use]
    pub fn ingress_ssrc(&self) -> Option<u32> {
        self.ingress.ssrc()
    }

    /// Extended highest inbound sequence received: `cycles << 16 | highest_seq` (RFC 3550 Appendix
    /// A.1) — the RTCP reception report's "extended highest sequence number" field.
    #[must_use]
    pub fn ingress_extended_highest_seq(&self) -> u32 {
        self.ingress.extended_highest_sequence()
    }

    /// Fold one inbound packet's arrival into the interarrival-jitter estimate (RFC 3550 §6.4.1 /
    /// §A.8). Call once per accepted ingress packet, right after [`MediaLeg::ingest_rtp`] (which
    /// records the packet's RTP timestamp). `arrival_micros` is the receive-time clock reading the
    /// datapath stamped on the datagram — *not* an actor-ingest time, so it reflects network timing.
    pub fn observe_arrival(&mut self, arrival_micros: u64) {
        self.ingress.observe_arrival(arrival_micros);
    }

    /// The current interarrival-jitter estimate in RTP-clock units (RFC 3550 §6.4.1), truncated to
    /// the `u32` the reception report carries.
    #[must_use]
    pub fn ingress_jitter(&self) -> u32 {
        self.ingress.jitter_rtp_units()
    }

    /// The interarrival-jitter estimate in **milliseconds** — the form the G.107 MOS estimator
    /// (`siphon-rtp-hep`) folds into one-way delay. Converts the RTP-clock-unit jitter by the ingress
    /// codec's clock rate.
    #[must_use]
    pub fn ingress_jitter_ms(&self) -> f64 {
        self.ingress.jitter_ms()
    }

    /// Residual inbound packet loss as a percentage — the jitter buffer's lost/concealed slots over
    /// the packets expected so far (`expected = highest − base + 1`, RFC 3550 Appendix A.3). The
    /// loss a listener actually hears, and the loss input to the MOS estimate. `0` before any packet.
    ///
    /// This is the **jitter-buffer-derived** loss (concealment count), distinct from the sequence-gap
    /// loss [`crate::ingress::IngressStats::loss_percent`] reports — a buffered leg measures the loss
    /// its playout actually concealed, so the leg overlays this on the shared receiver statistics.
    #[must_use]
    pub fn ingress_loss_percent(&self) -> f64 {
        let expected = self.ingress.expected();
        if expected == 0 {
            0.0
        } else {
            (self.jitter.stats().losses as f64 / f64::from(expected) * 100.0).clamp(0.0, 100.0)
        }
    }

    /// The fraction of packets lost **since the previous call** as the RTCP reception report's 8-bit
    /// fixed-point field (RFC 3550 §6.4.1 / Appendix A.3): `(lost_interval << 8) / expected_interval`,
    /// saturating at 255. Snapshots the cumulative `(expected, lost)` on every call, so successive
    /// reports each describe their own interval — the value resets per interval, it is **not**
    /// cumulative. Returns `0` before the first inbound packet, or for an interval that expected no
    /// packets. Deterministic: it reads only sequence / loss counters, never a clock. `expected` and
    /// `lost` are the same signals [`MediaLeg::ingress_loss_percent`] divides (jitter-buffer loss).
    #[must_use]
    pub fn fraction_lost_since_last_report(&mut self) -> u8 {
        if self.ingress.ssrc().is_none() {
            return 0;
        }
        let expected = self.ingress.expected();
        let lost = self.jitter.stats().losses as u32;
        let expected_interval = expected.wrapping_sub(self.fraction_lost_expected_prior);
        let lost_interval = lost.wrapping_sub(self.fraction_lost_lost_prior);
        self.fraction_lost_expected_prior = expected;
        self.fraction_lost_lost_prior = lost;
        // RFC 3550 A.3: no packets expected this interval, or no net loss ⇒ fraction 0. A "negative"
        // interval (duplicates outran loss) wraps to a large `u32`, caught by `> expected_interval`.
        if expected_interval == 0 || lost_interval == 0 || lost_interval > expected_interval {
            return 0;
        }
        ((u64::from(lost_interval) << 8) / u64::from(expected_interval)).min(255) as u8
    }

    /// Record a Sender Report **this leg has sent**: map its NTP timestamp's middle 32 bits (the value
    /// a peer echoes back as LSR, RFC 3550 §6.4.1) to `send_micros`, the logical send time, in a
    /// fixed-size ring (oldest entry overwritten). A later inbound reception report looks this send
    /// time up by its LSR to derive round-trip time. `send_micros` is a logical-clock reading (never
    /// `Instant::now()`), so the RTT it feeds stays deterministic in tests.
    pub fn record_sent_report(&mut self, ntp_timestamp: u64, send_micros: u64) {
        self.ingress.record_sent_report(ntp_timestamp, send_micros);
    }

    /// Consume an inbound reception report block that reports on **this leg's egress stream** and
    /// derive the round-trip time (RFC 3550 §6.4.1): `rtt = arrival − DLSR − LSR`, where LSR selects
    /// the Sender Report we sent (via [`MediaLeg::record_sent_report`]) and DLSR is the peer's
    /// processing delay. Returns the RTT in microseconds (also stored for [`MediaLeg::ingress_rtt_ms`]),
    /// or `None` when the block reports a different SSRC, carries no LSR, references an SR we do not
    /// recognise, or the arithmetic underflows (a stale / clock-skewed report). `arrival_micros` is a
    /// logical-clock reading, so the RTT is deterministic.
    pub fn record_reception_report(
        &mut self,
        block: &crate::rtcp::ReportBlock,
        arrival_micros: u64,
    ) -> Option<u64> {
        self.ingress
            .record_reception_report(self.egress_ssrc, block, arrival_micros)
    }

    /// The most recent round-trip time measured from an inbound reception report (µs), or `None` until
    /// one is derived (RFC 3550 §6.4.1).
    #[must_use]
    pub fn ingress_rtt_micros(&self) -> Option<u64> {
        self.ingress.rtt_micros()
    }

    /// The most recent measured round-trip time in **milliseconds** — the form the G.107 MOS estimator
    /// halves into one-way mouth-to-ear delay. `None` until an RTT is measured.
    #[must_use]
    pub fn ingress_rtt_ms(&self) -> Option<f64> {
        self.ingress.rtt_ms()
    }

    /// Record an inbound Sender Report: its NTP timestamp's middle 32 bits become LSR, and
    /// `arrival_micros` (when the SR was received) feeds DLSR (RFC 3550 §6.4.1).
    pub fn record_sender_report(&mut self, ntp_timestamp: u64, arrival_micros: u64) {
        self.last_sr_ntp_middle = ((ntp_timestamp >> 16) & 0xFFFF_FFFF) as u32;
        self.last_sr_arrival_micros = Some(arrival_micros);
    }

    /// LSR for the reception report — the middle 32 bits of the last inbound SR's NTP timestamp, or
    /// `0` if none has been seen (RFC 3550 §6.4.1).
    #[must_use]
    pub fn last_sr(&self) -> u32 {
        self.last_sr_ntp_middle
    }

    /// DLSR for the reception report — the delay between receiving the last SR and `now_micros`, in
    /// units of 1/65536 s, or `0` if no SR has been seen (RFC 3550 §6.4.1).
    #[must_use]
    pub fn delay_since_last_sr(&self, now_micros: u64) -> u32 {
        match self.last_sr_arrival_micros {
            Some(arrival) => {
                let delay_micros = u128::from(now_micros.saturating_sub(arrival));
                // µs → 1/65536 s: × 65536 / 1_000_000, saturating into the u32 field.
                ((delay_micros * 65_536) / 1_000_000).min(u128::from(u32::MAX)) as u32
            }
            None => 0,
        }
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
        assert_eq!(
            leg.next_pcm(&mut pcm).expect("conceal"),
            PcmFrame::Concealed(160)
        );
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
    fn interarrival_jitter_tracks_arrival_deviation() {
        // RFC 3550 §6.4.1 / §A.8: jitter is the smoothed mean deviation of consecutive transit times
        // (arrival − RTP timestamp). G.711 clocks RTP at 8 kHz, so 1 RTP unit = 125 µs.
        let mut leg = ulaw_leg();

        // Two packets arriving exactly in step with their timestamps ⇒ zero jitter.
        leg.ingest_rtp(&ulaw_packet(0, 0xFF)).expect("ingest 0"); // ts 0
        leg.observe_arrival(0); // arrival_rtp 0 ⇒ transit 0
        leg.ingest_rtp(&ulaw_packet(1, 0xFF)).expect("ingest 1"); // ts 160
        leg.observe_arrival(20_000); // arrival_rtp 160 ⇒ transit 0 ⇒ D 0
        assert_eq!(leg.ingress_jitter(), 0, "paced arrivals ⇒ no jitter");

        // A packet arriving 320 RTP units late ⇒ transit jumps to 160 ⇒ jitter += 160/16 = 10.
        leg.ingest_rtp(&ulaw_packet(2, 0xFF)).expect("ingest 2"); // ts 320
        leg.observe_arrival(60_000); // arrival_rtp 480 ⇒ transit 160 ⇒ D 160
        assert_eq!(leg.ingress_jitter(), 10);

        // Back in step (transit 160 again) ⇒ D 0 ⇒ jitter decays: 10 + (0 − 10)/16 = 9.375 ⇒ 9.
        leg.ingest_rtp(&ulaw_packet(3, 0xFF)).expect("ingest 3"); // ts 480
        leg.observe_arrival(80_000); // arrival_rtp 640 ⇒ transit 160 ⇒ D 0
        assert_eq!(leg.ingress_jitter(), 9);
    }

    #[test]
    fn sender_report_yields_lsr_and_dlsr() {
        // RFC 3550 §6.4.1: LSR = middle 32 bits of the last SR's NTP timestamp; DLSR = delay since
        // receiving it, in units of 1/65536 s.
        let mut leg = ulaw_leg();
        assert_eq!(leg.last_sr(), 0, "no SR seen yet");
        assert_eq!(leg.delay_since_last_sr(1_000_000), 0, "no SR ⇒ DLSR 0");

        leg.record_sender_report(0x1122_3344_5566_7788, 1_000_000); // received at 1.0 s
        assert_eq!(leg.last_sr(), 0x3344_5566, "middle 32 NTP bits");
        // 0.5 s later: 0.5 × 65536 = 32768 units of 1/65536 s.
        assert_eq!(leg.delay_since_last_sr(1_500_000), 32_768);
    }

    #[test]
    fn jitter_in_ms_converts_by_the_codec_clock() {
        let mut leg = ulaw_leg();
        // The schedule from `interarrival_jitter_tracks_arrival_deviation` settles jitter at 9 RTP
        // units, which at G.711's 8 kHz clock is 9/8000 s = 1.125 ms (the form the MOS estimator
        // consumes).
        leg.ingest_rtp(&ulaw_packet(0, 0xFF)).expect("0");
        leg.observe_arrival(0);
        leg.ingest_rtp(&ulaw_packet(1, 0xFF)).expect("1");
        leg.observe_arrival(20_000);
        leg.ingest_rtp(&ulaw_packet(2, 0xFF)).expect("2");
        leg.observe_arrival(60_000);
        leg.ingest_rtp(&ulaw_packet(3, 0xFF)).expect("3");
        leg.observe_arrival(80_000);
        assert!((leg.ingress_jitter_ms() - 1.125).abs() < 1e-6);
    }

    #[test]
    fn loss_percent_reflects_concealed_packets() {
        let mut leg = ulaw_leg();
        leg.ingest_rtp(&ulaw_packet(0, 0xFF)).expect("0");
        leg.ingest_rtp(&ulaw_packet(2, 0xFF)).expect("2"); // seq 1 lost
        let mut pcm = [0i16; 160];
        leg.next_pcm(&mut pcm).expect("p0"); // decode seq 0
        leg.next_pcm(&mut pcm).expect("conceal"); // seq 1 concealed ⇒ losses = 1
        leg.next_pcm(&mut pcm).expect("p2"); // decode seq 2
                                             // base seq 0, highest 2 ⇒ expected 3 packets; one concealed ⇒ 33.3 % loss.
        assert!((leg.ingress_loss_percent() - 100.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn fraction_lost_is_the_per_interval_8bit_ratio() {
        // RFC 3550 §6.4.1 / Appendix A.3: fraction = (lost_interval << 8) / expected_interval, over
        // just the interval since the previous report — not cumulative.
        let mut leg = ulaw_leg();
        let mut pcm = [0i16; 160];

        // Interval 1: base seq 0, highest 4 ⇒ expected 5; seq 1,2,3 concealed ⇒ 3 lost.
        leg.ingest_rtp(&ulaw_packet(0, 0xFF)).expect("0");
        leg.ingest_rtp(&ulaw_packet(4, 0xFF)).expect("4");
        for _ in 0..5 {
            leg.next_pcm(&mut pcm).expect("pop");
        }
        assert_eq!(leg.jitter_stats().losses, 3);
        // (3 << 8) / 5 = 768 / 5 = 153.
        assert_eq!(leg.fraction_lost_since_last_report(), 153);

        // An immediate second report describes a zero-length interval ⇒ resets to 0 (not cumulative).
        assert_eq!(leg.fraction_lost_since_last_report(), 0);

        // Interval 2: highest advances to 7 ⇒ expected_interval 3; seq 6 concealed ⇒ lost_interval 1.
        leg.ingest_rtp(&ulaw_packet(5, 0xFF)).expect("5");
        leg.ingest_rtp(&ulaw_packet(7, 0xFF)).expect("7");
        for _ in 0..3 {
            leg.next_pcm(&mut pcm).expect("pop");
        }
        // (1 << 8) / 3 = 256 / 3 = 85 — a distinct per-interval value.
        assert_eq!(leg.fraction_lost_since_last_report(), 85);
    }

    #[test]
    fn rtt_from_reception_report_against_a_seeded_sent_sr_table() {
        use crate::rtcp::ReportBlock;
        let mut leg = ulaw_leg(); // egress SSRC 0xABCD_1234

        // We sent an SR at logical time 1.0 s whose NTP middle-32 is 0xDEAD_BEEF.
        leg.record_sent_report(0x0000_DEAD_BEEF_0000, 1_000_000);

        // The peer's reception report on our egress SSRC echoes that LSR and reports DLSR = 0.5 s
        // (0.5 × 65536 = 32768 units of 1/65536 s). It arrives at 2.0 s.
        let block = ReportBlock {
            ssrc: 0xABCD_1234,
            fraction_lost: 0,
            cumulative_lost: 0,
            highest_sequence: 0,
            jitter: 0,
            last_sender_report: 0xDEAD_BEEF,
            delay_since_last_sr: 32_768,
        };
        // rtt = arrival − DLSR − LSR-send = 2_000_000 − 500_000 − 1_000_000 = 500_000 µs.
        assert_eq!(
            leg.record_reception_report(&block, 2_000_000),
            Some(500_000)
        );
        assert_eq!(leg.ingress_rtt_micros(), Some(500_000));
        assert!((leg.ingress_rtt_ms().expect("rtt") - 500.0).abs() < 1e-9);

        // A block echoing an LSR we never sent yields no RTT (rtt unknown).
        let unknown = ReportBlock {
            last_sender_report: 0x0BAD_0BAD,
            ..block
        };
        assert_eq!(leg.record_reception_report(&unknown, 3_000_000), None);

        // A block reporting on a different SSRC is not about our stream ⇒ no RTT.
        let other_source = ReportBlock {
            ssrc: 0x0000_0001,
            ..block
        };
        assert_eq!(leg.record_reception_report(&other_source, 3_000_000), None);
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
        assert_eq!(
            receiver.next_pcm(&mut pcm_out).expect("decode"),
            PcmFrame::Decoded(160)
        );

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
        let payload_len = source
            .encode_payload(&pcm, &mut payload)
            .expect("encode once");

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
        assert_eq!(
            packet_a.payload, packet_b.payload,
            "one encode, shared payload"
        );
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
        let combined_len = combined
            .encode_rtp(&pcm, &mut via_combined)
            .expect("encode_rtp");

        assert_eq!(&via_split[..split_len], &via_combined[..combined_len]);
        assert_eq!(split.egress_ssrc(), combined.egress_ssrc());
    }

    proptest::proptest! {
        /// Folding arbitrary arrival times into the interarrival-jitter estimate (RFC 3550 §6.4.1)
        /// never panics and keeps the estimate a finite, non-negative value — the recurrence is
        /// bounded for any input (wrapping `u32`/`i32` transit arithmetic, §A.8).
        #[test]
        fn observe_arrival_keeps_jitter_finite(
            arrivals in proptest::collection::vec(0u64..50_000_000, 0..64),
        ) {
            let mut leg = ulaw_leg();
            for (index, arrival) in arrivals.into_iter().enumerate() {
                let _ = leg.ingest_rtp(&ulaw_packet(index as u16, 0xFF));
                leg.observe_arrival(arrival);
                let jitter = leg.ingress_jitter_ms();
                proptest::prop_assert!(
                    jitter.is_finite() && jitter >= 0.0,
                    "jitter must stay finite ≥ 0, got {jitter}"
                );
            }
        }
    }
}
