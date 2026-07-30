//! The userspace media slow path: per-call transcode / record / DTMF-extraction actors.
//!
//! Where the datapath `Forward` fast path relays an opaque datagram untouched and the
//! [`crate::srtp_bridge`] terminates SRTP, a **media-processing** call sets every audio endpoint to
//! [`FlowAction::Redirect`](siphon_rtp_datapath::FlowAction::Redirect) and the redirect dispatcher
//! routes each datagram to that call's [`MediaCall`] actor. The actor:
//!
//! - re-enforces the signalled-source gate (RTPBleed defence — `Redirect` bypasses the datapath's
//!   gate, exactly as the SRTP bridge must, docs/security-and-nat.md §4 layer 2),
//! - latches the observed source so the reverse direction replies symmetrically (RFC 3550),
//! - transcodes audio between the two legs' negotiated codecs (decode → resample → encode),
//! - relays RTCP and unknown packets verbatim (RFC 5761 demux),
//! - extracts RFC 4733 telephone-events to `Event::Dtmf` and repacketizes them onto the egress
//!   stream, and
//! - optionally records each direction's decoded audio to a WAV file on teardown.
//!
//! Transcode is **packet-driven**, not clock-driven: each ingress packet produces one egress packet
//! (the receiving endpoint owns the playout jitter buffer), so the actor needs no playout ticker.
//! The per-packet transform lives in [`MediaCall::process`], which is pure (datagrams in → datagrams
//! + events out) so it unit-tests deterministically without sockets.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use dashmap::DashMap;
use siphon_rtp_srtp::leg::{SecureLeg, SecureLegRollover};

use siphon_rtp_codec::cn::Cn;
use siphon_rtp_codec::{Decoder, Encoder};
use siphon_rtp_datapath::{Datapath, EndpointId, RxPacket, SourceFilter};
use siphon_rtp_dsp::resample::Resampler;
use siphon_rtp_dsp::{EchoCanceller, NoiseSuppressor};
use siphon_rtp_media::dtmf::{DtmfDetector, DtmfSequence, DtmfStep};
use siphon_rtp_media::fanout::MediaSink;
use siphon_rtp_media::ingress::IngressStats;
use siphon_rtp_media::pcap::CapturedPacket;
use siphon_rtp_media::player::PcmPlayer;
use siphon_rtp_media::repacketize::Repacketizer;
use siphon_rtp_media::rtp::{write_packet, RtpHeader, RtpPacket};
use siphon_rtp_media::wav::WavRecorder;
use siphon_rtp_proto::{Event, PlayEndReason};

/// The playout-clock tick driving injected media (PlayMedia / PlayDtmf): one egress packet per
/// 20 ms, the telephony default ptime (RFC 3551).
pub const INJECT_TICK: std::time::Duration = std::time::Duration::from_millis(20);

/// How many [`INJECT_TICK`]s between periodic per-leg [`Event::CallQuality`] reports — 250 × 20 ms ≈
/// 5 s, the same reporting cadence the conference actor uses for its quality events / RTCP SRs.
const QUALITY_INTERVAL_TICKS: u64 = 250;

/// The comfort-noise level (`-dBov`, RFC 3389 §3.1) a single-leg local-answer / IVR leg emits while
/// idle — a faint background floor so the caller hears "nothing to say" rather than dead air or its
/// own audio looped back. Larger = quieter (further below full scale): at 75 the RMS is ~32768·10⁻³·⁷⁵
/// ≈ 6 (peak ≈ ±10), a barely-perceptible floor. Kept deliberately low because the generated noise is
/// spectrally flat (RFC 3389 §3.2 shaping is unimplemented), so flat white noise reads as a harsher
/// hiss than a real, low-passed room tone at the same level. Sent as the level byte of a CN packet
/// when CN was negotiated, else as the target level of the audio-encoded fallback noise.
const COMFORT_NOISE_LEVEL_DBOV: u8 = 75;

/// Largest RTP packet the egress scratch buffers accommodate.
const MAX_RTP: usize = 1500;
/// Largest decoded PCM frame (48 kHz × 40 ms mono, a safe ceiling for any telephony frame).
const MAX_PCM: usize = 1920;

/// Echo-canceller adaptive-filter tail, in milliseconds at the near-end codec rate. 64 ms (512 taps
/// @ 8 kHz / 1024 @ 16 kHz) spans the line/acoustic residual impulse-response *after* the GCC-PHAT
/// estimator removes the bulk transport delay — the MDF partitioned-block backend covers it at
/// O(N log N), so a generous tail is cheap.
const AEC_TAIL_MILLIS: u32 = 64;
/// GCC-PHAT bulk-delay search range, in milliseconds at the near-end codec rate. 128 ms (1024 samples
/// @ 8 kHz / 2048 @ 16 kHz) covers the loudspeaker→microphone acoustic path plus the network/jitter
/// round-trip between the reference the engine sent toward a party and the echo that returns on that
/// party's uplink (a media-relay echo path is longer than a handset's, so search wide).
const AEC_DELAY_SEARCH_MILLIS: u32 = 128;

/// The SSRC-consistent symmetric-RTP latch for a `Redirect`-path leg — the userspace mirror of the
/// datapath's `update_latch` (docs/security-and-nat.md §4 layer 3; RFC 3550 §8, RFC 4961). The reverse
/// egress destination follows a genuine NAT rebind (a new source that keeps the stream's SSRC) but
/// resists a hijack spray (a new source with a different SSRC). Only **authenticated** RTP is ever
/// offered here — on a secure leg the caller offers a packet only *after* SRTP `unprotect` succeeds —
/// so a forged, auth-failing packet can never move the reply direction (the fix for the pre-auth,
/// no-SSRC-check re-latch).
#[derive(Default)]
pub(crate) struct SymmetricLatch {
    source: Option<SocketAddr>,
    ssrc: Option<u32>,
}

impl SymmetricLatch {
    /// Offer an accepted RTP packet's `source` and `ssrc`. Returns `Some(source)` when the reverse
    /// egress should be (re)pointed there, or `None` to keep the current latch (a likely hijack: a new
    /// source carrying a different SSRC than the latched stream).
    pub(crate) fn observe(&mut self, source: SocketAddr, ssrc: u32) -> Option<SocketAddr> {
        match self.source {
            // First accepted stream member: latch its source and record its SSRC.
            None => {
                self.source = Some(source);
                self.ssrc = Some(ssrc);
                Some(source)
            }
            // Same source: stay latched (refresh the SSRC we track for it).
            Some(current) if current == source => {
                self.ssrc = Some(ssrc);
                Some(source)
            }
            // New source keeping the SSRC — a genuine NAT rebind (RFC 3550 §8): follow it.
            Some(_) if self.ssrc == Some(ssrc) => {
                self.source = Some(source);
                Some(source)
            }
            // New source with a different SSRC — a spray/hijack: reject, keep the current latch.
            Some(_) => None,
        }
    }
}

/// The RTP SSRC (RFC 3550 §5.1, bytes 8..12) of an RTP media packet, or `None` when `data` is not one
/// (too short, wrong version, or RTCP — RFC 5761: RTCP carries no comparable per-stream SSRC at this
/// offset, so it never drives the SSRC re-latch). Mirrors the datapath's `rtp_ssrc` for the userspace
/// relay-only path, which forwards the datagram verbatim and so does not otherwise parse it.
fn rtp_source_ssrc(data: &[u8]) -> Option<u32> {
    if data.len() < 12 || data[0] >> 6 != 2 {
        return None;
    }
    let payload_type = data[1] & 0x7f;
    if (64..=95).contains(&payload_type) {
        return None; // RTCP (RFC 5761 §4)
    }
    Some(u32::from_be_bytes([data[8], data[9], data[10], data[11]]))
}

/// A preallocated FIFO of far-end **reference** PCM: the egress samples one direction produced toward
/// its receiving party, buffered for the *opposite* direction's [`EchoCanceller`] to cancel that
/// party's uplink echo against (the audio played toward a party is the reference for cancelling the
/// echo of it on that party's send path — spec §"Reference/near-end plumbing"). One contiguous ring;
/// bounded with drop-oldest, since a producer/consumer interleave skew must never grow it without
/// limit and late reference audio is worthless (bounded media backpressure: drop-oldest, never grow).
/// Zero per-frame heap allocation: the buffer is preallocated and `push`/`read_into` are copy loops.
struct EchoReference {
    /// Contiguous ring storage (`capacity` samples), oldest sample at `head`.
    buffer: Box<[i16]>,
    /// Index of the oldest valid sample.
    head: usize,
    /// Number of valid samples currently buffered (`0..=capacity`).
    length: usize,
    /// The sample rate the buffered reference PCM is at — the producing direction's egress codec
    /// rate, which (by the offer/answer model) equals the consuming direction's near-end rate.
    sample_rate_hz: u32,
}

impl EchoReference {
    /// A ring holding up to `capacity` reference samples at `sample_rate_hz`.
    fn new(capacity: usize, sample_rate_hz: u32) -> Self {
        Self {
            buffer: vec![0i16; capacity].into_boxed_slice(),
            head: 0,
            length: 0,
            sample_rate_hz,
        }
    }

    /// Append `samples` to the ring, dropping the oldest samples first when the ring is full so the
    /// **newest** reference is always retained (a stalled consumer must not pin stale far-end audio).
    fn push(&mut self, samples: &[i16]) {
        let capacity = self.buffer.len();
        if capacity == 0 {
            return;
        }
        for &sample in samples {
            if self.length == capacity {
                // Full: overwrite the oldest slot and advance `head` (drop-oldest, length unchanged).
                self.buffer[self.head] = sample;
                self.head = (self.head + 1) % capacity;
            } else {
                let tail = (self.head + self.length) % capacity;
                self.buffer[tail] = sample;
                self.length += 1;
            }
        }
    }

    /// Drain the oldest `min(out.len(), length)` samples into `out` (frame-synchronous with the
    /// near-end frame the caller is cancelling), zero-padding any shortfall so `out` is fully valid.
    /// Returns the number of real (non-padded) reference samples delivered.
    fn read_into(&mut self, out: &mut [i16]) -> usize {
        let capacity = self.buffer.len();
        let take = out.len().min(self.length);
        for slot in out[..take].iter_mut() {
            *slot = self.buffer[self.head];
            self.head = (self.head + 1) % capacity;
        }
        self.length -= take;
        for slot in out[take..].iter_mut() {
            *slot = 0;
        }
        take
    }
}

/// Build the engine's default [`EchoCanceller`] for a leg at `sample_rate_hz` (the near-end / uplink
/// codec rate), or `None` when the rate is one the canceller rejects (< 8 kHz or not a 50 Hz multiple,
/// or an MDF tail past its cap) — the leg is then transcoded/bridged uncancelled rather than failing.
///
/// The backend is the **MDF partitioned-block frequency-domain** filter with automatic GCC-PHAT
/// bulk-delay estimation and the two-path/NCC double-talk detector — the safe, robust default: the
/// estimator recovers the unknown loudspeaker→mic + network round-trip delay, the MDF's per-block NCC
/// keeps the filter from ever learning (and thus cancelling) the near-end talker, and it re-converges
/// cleanly after a delay re-lock. MDF is chosen here for the media-relay path's **long** echo tail —
/// its partitioned FFT covers a wide tail at O(N log N); the time-domain two-path backend in
/// `siphon-rtp-dsp` (`cancel_two_path`) is the alternative for a short handset tail, and both backends
/// re-converge after a delay re-lock. The MDF adds a fixed ~16 ms block algorithmic latency the
/// receiving jitter buffer absorbs; its per-frame cost is tens of µs, so it stays inline on the actor
/// (no `spawn_blocking`). The residual-echo WOLA post-filter (a further ~32 ms latency) is left off:
/// it has no production route in the shipped engine and is out of scope here. All state is preallocated
/// ⇒ `cancel` allocates nothing on the hot path. Shared by the 2-party transcode path
/// ([`Direction::new`]) and the WS voice-AI bridge so both cancel with the identical, single-sourced
/// configuration.
pub(crate) fn build_echo_canceller(sample_rate_hz: u32) -> Option<EchoCanceller> {
    let tail_samples = (sample_rate_hz * AEC_TAIL_MILLIS / 1000).max(1) as usize;
    let search_range = (sample_rate_hz * AEC_DELAY_SEARCH_MILLIS / 1000).max(1) as usize;
    match EchoCanceller::with_mdf_delay_estimation(sample_rate_hz, tail_samples, search_range) {
        Ok(canceller) => Some(canceller.with_two_path_dtd()),
        Err(error) => {
            tracing::warn!(
                %error,
                sample_rate_hz,
                "echo cancellation requested but unsupported at the codec rate; leaving it uncancelled"
            );
            None
        }
    }
}

/// An RTP/RTCP datagram the pipeline wants to transmit: from `endpoint` toward `dst`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// The endpoint (socket) to transmit from.
    pub endpoint: EndpointId,
    /// Where to transmit it (the peer's latched/signalled address).
    pub dst: SocketAddr,
    /// The datagram bytes.
    pub data: Bytes,
}

/// A SIPREC / monitor raw-RTP tee target on one direction's ingress: the original ingress RTP is
/// copied verbatim out `subscriber_endpoint` toward `srs_dst` (a Session Recording Server, RFC 7866
/// §6). The tee carries the source leg's **negotiated codec, byte-for-byte** — no decode/re-encode —
/// so it works for any codec (G.711, AMR-WB, …) regardless of whether the engine has an encoder for
/// it. The subscriber is send-only: the engine never installs an inbound flow on `subscriber_endpoint`
/// (no RTPBleed surface — docs/security-and-nat.md §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawTee {
    /// The engine endpoint the forked RTP is transmitted from (send-only toward the SRS).
    pub subscriber_endpoint: EndpointId,
    /// The SRS's RTP address (from `subscribe_answer`).
    pub srs_dst: SocketAddr,
}

/// One direction of a media-processing call: ingress codec → (resample) → egress codec.
///
/// "Direction" means the flow of media from one party toward the other. `a_to_b` decodes party A's
/// ingress and encodes it for party B; `b_to_a` is the reverse. The egress sequence/timestamp/SSRC
/// belong to the *synthesized* stream the engine sends to the receiving party.
///
/// A direction may run in **relay-only** mode (`relay_only`): it forwards the ingress RTP verbatim to
/// the peer (no decode/encode), used when a plain passthrough call is promoted to userspace so a
/// SIPREC raw tee can be added to it. In that mode the codec fields are unused (a no-op G.711 pair).
/// Idle-egress comfort noise for a **single-leg** local-answer / IVR leg (RFC 3389). Such a leg faces
/// the caller on *both* directions, so re-encoding the decoded ingress would loop the caller's own
/// audio back to it (self-echo). Instead the playout tick fills the idle egress with a continuous
/// comfort-noise stream: a 1-byte CN packet on the negotiated [`Self::cn_pt`] when the caller offered
/// CN (its own generator renders it), else a low-level noise frame from [`Self::generator`] encoded in
/// the leg's audio codec. Either way the egress sequence/timestamp advance continuously, so a
/// following prompt hands over with no gap or clip. `Some` on a `Direction` marks it comfort-idle.
struct ComfortNoise {
    /// RFC 3389 CN egress payload type when the caller negotiated CN at the egress clock rate; `None`
    /// ⇒ audio-encoded low-level noise on the leg's own audio codec.
    cn_pt: Option<u8>,
    /// Noise source for the audio-encoded fallback (and unused when `cn_pt` is `Some`).
    generator: Cn,
}

pub struct Direction {
    /// The endpoint datagrams arrive on for this direction (the sending party's engine socket).
    ingress_endpoint: EndpointId,
    /// Signalled-source gate for the sending party (RTPBleed defence on the Redirect path).
    accepted_source: SourceFilter,
    /// The SSRC-consistent symmetric latch for this direction's ingress stream. When an accepted
    /// (authenticated + source-gated) RTP packet arrives, the *reverse* direction's `egress_dst` is
    /// re-pointed to the observed source only when it is SSRC-consistent — a forged/auth-failing or
    /// wrong-SSRC packet never moves the reply direction (docs/security-and-nat.md §4 layer 3).
    source_latch: SymmetricLatch,
    /// The endpoint to transmit from (the receiving party's engine socket).
    egress_endpoint: EndpointId,
    /// Where to transmit (the receiving party's address; latched to its observed source).
    egress_dst: SocketAddr,
    /// When `true`, forward the ingress RTP verbatim to the peer (no transcode) — a promoted
    /// passthrough relay. The codec fields below are unused in this mode.
    relay_only: bool,
    /// SIPREC / monitor raw-RTP tee targets: each receives the **original ingress RTP** byte-for-byte
    /// (RFC 7866 §6). Independent of transcode/relay — added/removed by `subscribe_answer`/`unsubscribe`.
    raw_tee: Vec<RawTee>,
    decoder: Box<dyn Decoder>,
    encoder: Box<dyn Encoder>,
    /// Sample-rate converter when the ingress codec rate differs from the egress codec rate.
    resampler: Option<Resampler>,
    /// Single-channel noise suppression on this direction's decoded ingress audio, applied in place
    /// before record/fork/silence/resample/encode so every downstream consumer sees the cleaned
    /// signal. `Some` only when the control requested it *and* the ingress rate is 8/16 kHz (built and
    /// rate-gated in `Direction::new`); introduces the suppressor's WOLA latency on this leg.
    noise_suppressor: Option<NoiseSuppressor>,
    /// Acoustic/line echo canceller for **this direction's near-end** (the decoded ingress uplink),
    /// applied post-decode / post-NS, pre-resample/pre-encode (in the ingress codec's native-rate
    /// domain) when the leg enabled the `echo_cancellation` profile flag. Its far-end **reference** is
    /// the *opposite* direction's [`Direction::echo_reference`] — the PCM the engine most recently sent
    /// toward this party — handed in per packet by [`MediaCall::process`] (no `Arc<Mutex>` over leg
    /// state, mirroring [`Direction::echo_into`]). `None` on a leg without the flag, or when the
    /// ingress codec rate is one the canceller rejects (< 8 kHz or not a 50 Hz multiple), in which case
    /// the audio is transcoded uncancelled. Preallocated ⇒ its per-frame `cancel` allocates nothing.
    echo_canceller: Option<EchoCanceller>,
    /// A preallocated ring of **this direction's** egress PCM toward its receiving party (captured in
    /// [`Direction::emit_pcm`], at the egress codec rate), read frame-synchronously by the *opposite*
    /// direction's [`Direction::echo_canceller`] as the far-end reference. Present iff the *opposite*
    /// direction cancels (it needs this direction's egress as its reference); `None` otherwise, so emit
    /// captures nothing.
    echo_reference: Option<EchoReference>,
    egress_sequence: u16,
    egress_timestamp: u32,
    egress_ssrc: u32,
    egress_payload_type: u8,
    /// Egress PCM samples per frame at the codec's *native* rate (sizes the encode work / ptime).
    egress_frame_samples: u32,
    /// Egress RTP timestamp step per packet, in *RTP-clock* units (ptime × RTP clock ÷ 1000). Equal
    /// to `egress_frame_samples` for every codec whose RTP clock matches its sample rate, but not for
    /// G.722 (16 kHz audio, 8 kHz RTP clock; RFC 3551 §4.5.2) — there it is half the sample count.
    egress_timestamp_increment: u32,
    /// Re-frames the decoded/resampled ingress PCM to the egress `ptime` (rtpengine `ptime=<N>` override
    /// or an ingress↔egress `a=ptime` mismatch). Accumulates egress-domain samples and drains exactly
    /// `egress_frame_samples` per emitted packet, so one ingress frame can yield zero-or-many egress
    /// packets. Sample-exact FIFO; preallocated (zero per-frame heap alloc on the hot path).
    repacketizer: Repacketizer,
    /// Pending RFC 3550 §5.1 marker: set when an ingress packet flags a talkspurt start (marker bit),
    /// consumed by the next emitted egress packet — never a blind per-packet copy, since one ingress
    /// packet maps to zero-or-many egress packets under repacketization.
    pending_marker: bool,
    /// Ingress RFC 4733 telephone-event payload type, if negotiated.
    telephone_event_in: Option<u8>,
    /// Egress RFC 4733 telephone-event payload type (what the receiving party expects).
    telephone_event_out: Option<u8>,
    dtmf: DtmfDetector,
    /// Records the decoded ingress audio when the call is recorded.
    recorder: Option<WavRecorder>,
    /// SIPREC / monitor fork sinks fed the decoded ingress audio (post-decode, pre-encode — the same
    /// PCM the recorder sees). Each re-encodes for a send-only subscriber (a Session Recording Server,
    /// RFC 7866 §6). Empty unless a `subscribe_request`/`subscribe_answer` attached one.
    forks: Vec<Box<dyn MediaSink>>,
    /// Replace egress audio with comfort silence (digit-suppression / hold).
    silenced: bool,
    /// Drop egress audio entirely (not even silence).
    blocked: bool,
    /// Suppress relaying this leg's RFC 4733 telephone-event (DTMF) packets to the peer while still
    /// detecting them (`block DTMF`). When set, an ingress telephone-event still fires the control
    /// plane's `Event::Dtmf` (observability) but is not repacketized toward the peer — the digit is
    /// seen by the controller but not heard by the far side. Independent of `blocked` (audio drop).
    dtmf_blocked: bool,
    /// Egress codec native sample rate, for resampling injected prompt audio onto this stream.
    egress_sample_rate: u32,
    /// An active prompt / DTMF injection on this egress direction (PlayMedia / PlayDtmf). While set,
    /// transcoded audio toward this party is suppressed and the injected media plays instead.
    injection: Option<Injection>,
    /// Idle-egress comfort noise for a **single-leg** local-answer / IVR leg (`Some` only on that
    /// leg's caller-facing egress — [`MediaCall::with_comfort_idle`]). When set, [`Direction::handle`]
    /// must not loop the caller's own audio back (self-echo): it decodes for recording / DTMF but
    /// emits nothing, and the playout tick fills the idle egress with comfort noise instead (see
    /// [`ComfortNoise`]). A player injection overrides it; the `echo` verb reflects via `echo_into`.
    comfort: Option<ComfortNoise>,
    /// SDES-SRTP on a **secure + transcoding** leg (BGCF/SBC: e.g. a secure AMR-WB access leg ↔ a
    /// plaintext G.711 PSTN leg). When the *ingress* faces the secure peer, `secure_ingress` decrypts
    /// each datagram (SRTP→RTP / SRTCP→RTCP) before decode; when the *egress* faces the secure peer,
    /// `secure_egress` encrypts each transcoded/relayed datagram before transmit. Both reference the
    /// one shared [`SecureLeg`] for the call (single-owner actor ⇒ the `Mutex` is uncontended). `None`
    /// on a plaintext leg — the existing transcode path is unchanged.
    secure_ingress: Option<Arc<Mutex<SecureLeg>>>,
    secure_egress: Option<Arc<Mutex<SecureLeg>>>,
    /// Receiver-side reception statistics for this direction's inbound stream (RFC 3550 §6.4.1): the
    /// loss / jitter (and RTT, when measured) feeding the periodic [`Event::CallQuality`] a 2-party
    /// transcode call reports on the control channel — the transcode counterpart to the conference
    /// per-participant quality report. Fed once per accepted ingress RTP packet in
    /// [`Direction::handle`]; loss is the sequence-gap model (this direction has no playout jitter
    /// buffer — the receiving endpoint owns that). Left inert on a relay-only direction (never fed).
    ingress: IngressStats,
    /// The G.107 codec class (ITU-T G.107) of this direction's **ingress** stream, for the MOS in its
    /// quality report — the codec the sending party used (what this direction decodes).
    ingress_mos_codec: siphon_rtp_hep::mos::Codec,
    /// Running min / mean / max of this direction's periodic MOS (and peak jitter / loss) across the
    /// whole call, for the end-of-call CDR ([`Event::CallSummary`]). Folded one sample per periodic
    /// quality tick (~5 s) by [`Direction::accumulate_quality`]; never touched on the per-packet path.
    quality: QualityAggregate,
}

/// One periodic quality reading for a direction: an ITU-T G.107 MOS and the RFC 3550 loss/jitter it
/// was derived from. Shared by the live [`Event::CallQuality`] emit and the end-of-call aggregate so
/// both read one consistent computation.
#[derive(Clone, Copy)]
struct QualitySample {
    mos: f64,
    jitter_ms: f64,
    loss_percent: f64,
}

/// Running end-of-call quality accumulation for one [`Direction`]'s ingress stream: the min / mean /
/// max of its periodic G.107 MOS samples (each with the call-relative time it was taken), plus the
/// peak RFC 3550 jitter and loss seen across the call. Fed one sample per periodic quality tick
/// (~5 s) by [`Direction::accumulate_quality`], so it is plain arithmetic over already-computed
/// estimates — no per-packet work and zero allocation. Read at teardown for the call's CDR: the
/// instantaneous loss/jitter there come straight from [`IngressStats`], while these carry the
/// over-the-call shape a single final snapshot cannot (rtpengine's "avg/min/max MOS ... at 0:33").
#[derive(Debug, Default, Clone)]
pub(crate) struct QualityAggregate {
    samples: u32,
    mos_sum: f64,
    mos_min: f64,
    mos_min_at_ms: u64,
    mos_max: f64,
    mos_max_at_ms: u64,
    jitter_ms_max: f64,
    loss_percent_max: f64,
}

impl QualityAggregate {
    /// Fold one periodic quality sample, taken at call-relative time `at_ms`, into the running stats.
    fn record(&mut self, mos: f64, jitter_ms: f64, loss_percent: f64, at_ms: u64) {
        if self.samples == 0 || mos < self.mos_min {
            self.mos_min = mos;
            self.mos_min_at_ms = at_ms;
        }
        if self.samples == 0 || mos > self.mos_max {
            self.mos_max = mos;
            self.mos_max_at_ms = at_ms;
        }
        self.jitter_ms_max = self.jitter_ms_max.max(jitter_ms);
        self.loss_percent_max = self.loss_percent_max.max(loss_percent);
        self.mos_sum += mos;
        self.samples += 1;
    }

    /// Number of samples folded (`0` ⇒ no inbound media was ever measured on this direction).
    pub(crate) fn samples(&self) -> u32 {
        self.samples
    }

    /// Mean MOS across the call, or `None` if no sample was ever taken.
    pub(crate) fn mos_average(&self) -> Option<f64> {
        (self.samples > 0).then(|| self.mos_sum / f64::from(self.samples))
    }

    /// Lowest MOS sample (worst instant), or `None` if none was taken.
    pub(crate) fn mos_min(&self) -> Option<f64> {
        (self.samples > 0).then_some(self.mos_min)
    }

    /// Call-relative time (ms) of the lowest MOS sample.
    pub(crate) fn mos_min_at_ms(&self) -> u64 {
        self.mos_min_at_ms
    }

    /// Highest MOS sample (best instant), or `None` if none was taken.
    pub(crate) fn mos_max(&self) -> Option<f64> {
        (self.samples > 0).then_some(self.mos_max)
    }

    /// Call-relative time (ms) of the highest MOS sample.
    pub(crate) fn mos_max_at_ms(&self) -> u64 {
        self.mos_max_at_ms
    }

    /// Peak interarrival jitter (ms) observed across the call.
    pub(crate) fn jitter_ms_max(&self) -> f64 {
        self.jitter_ms_max
    }

    /// Peak packet loss (%) observed across the call.
    pub(crate) fn loss_percent_max(&self) -> f64 {
        self.loss_percent_max
    }
}

/// One direction's end-of-call quality, snapshotted from the media actor at teardown for the CDR: the
/// RFC 3550 reception counters/estimates for the stream this direction *received*, plus its running
/// G.107 MOS aggregate. `rtt_ms` is `Some` only when a reception report yielded a round-trip time
/// (usually only the conference path); on the relay/transcode path it stays `None` and the CDR marks
/// the MOS `loss+jitter`-based, never fabricating a zero RTT.
#[derive(Debug, Clone, Default)]
pub struct DirectionQuality {
    pub ssrc: Option<u32>,
    pub packets_received: u64,
    pub packets_expected: u32,
    pub packets_lost: u32,
    pub loss_percent: f64,
    pub jitter_ms: f64,
    /// Peak interarrival jitter (ms) / packet loss (%) sampled across the call (worst instant), the
    /// companion to the cumulative `jitter_ms` / `loss_percent` above.
    pub jitter_ms_max: f64,
    pub loss_percent_max: f64,
    pub rtt_ms: Option<f64>,
    pub mos_samples: u32,
    pub mos_average: Option<f64>,
    pub mos_min: Option<f64>,
    pub mos_min_at_ms: u64,
    pub mos_max: Option<f64>,
    pub mos_max_at_ms: u64,
}

/// A media call's per-direction end-of-call quality: `a_to_b` measures what the offerer (`from_tag`)
/// sent, `b_to_a` what the answerer (`to_tag`) sent. The engine requests this over the actor's mailbox
/// at teardown (before the task is aborted) to assemble the call's CDR.
#[derive(Debug, Clone, Default)]
pub struct FinalCallQuality {
    pub a_to_b: DirectionQuality,
    pub b_to_a: DirectionQuality,
}

/// One playout tick's egress action, computed while the injection is borrowed and applied after.
enum InjectStep {
    /// Encode + send this prompt PCM frame at the egress rate.
    Audio(Vec<i16>),
    /// Send this telephone-event packet (bytes already framed by the generator).
    Dtmf {
        bytes: [u8; 4],
        marker: bool,
        payload_type: u8,
        timestamp: u32,
    },
    /// Inter-digit silence in a multi-digit DTMF sequence — emit nothing this tick, but keep the
    /// injection active (the next digit is still to come; RFC 4733 gap between events).
    DtmfSilence,
    /// The injection finished — clear it and resume transcode.
    Exhausted,
    /// No injection active.
    Idle,
}

/// A `play_media` prompt that just ended, reported by the injection paths so the actor can emit the
/// matching [`Event::PlayFinished`]. Carries the accept's `play_id` (the load-bearing correlator),
/// how it ended, and the milliseconds actually played (for observability / CDR).
struct FinishedPlay {
    play_id: u64,
    reason: PlayEndReason,
    played_ms: u64,
}

/// Media injected onto an egress direction by a control verb.
enum Injection {
    /// A prompt / announcement from [`super::engine`]'s `PlayMedia`, resampled to the egress rate.
    Audio {
        player: PcmPlayer,
        resampler: Option<Resampler>,
        /// The accept's playback id; the [`Event::PlayFinished`] emitted when this prompt ends
        /// (drains / is stopped / superseded / aborted) carries it so a controller correlates the
        /// completion with the accept it holds.
        play_id: u64,
        /// Milliseconds played so far (one ptime per emitted frame), reported as `played_ms`.
        played_ms: u64,
    },
    /// An RFC 4733 DTMF sequence from `PlayDtmf` (`code`, one event per digit), sharing the egress
    /// stream's SSRC. Each digit event carries its own start timestamp (`base_timestamp` plus the
    /// sequence step's offset), holding it constant across that event's packets (RFC 4733 §2.5.1.2).
    Dtmf {
        sequence: DtmfSequence,
        payload_type: u8,
        /// The RTP timestamp of the sequence's first event; later digit events start at this plus the
        /// step's `timestamp_offset` so the peer resolves each press separately (RFC 4733 §2.5.1.2).
        base_timestamp: u32,
    },
}

/// Per-direction construction parameters, built by the engine from the negotiated SDP.
pub struct DirectionConfig {
    pub ingress_endpoint: EndpointId,
    pub accepted_source: SourceFilter,
    pub egress_endpoint: EndpointId,
    pub egress_dst: SocketAddr,
    pub decoder: Box<dyn Decoder>,
    pub encoder: Box<dyn Encoder>,
    pub egress_ssrc: u32,
    pub egress_payload_type: u8,
    pub telephone_event_in: Option<u8>,
    pub telephone_event_out: Option<u8>,
    /// `Some(WavRecorder)` to record this direction's decoded audio.
    pub recorder: Option<WavRecorder>,
    /// Request noise suppression on this direction's decoded ingress audio. Built and rate-gated (to
    /// 8/16 kHz) in `Direction::new`; inert on an unsupported ingress rate.
    pub noise_suppression: bool,
    /// Cancel this direction's near-end (uplink) echo, referenced against the opposite direction's
    /// egress toward the same party. Built at the ingress codec's native rate; a codec at a rate the
    /// canceller rejects (< 8 kHz or not a 50 Hz multiple) transcodes uncancelled.
    pub echo_cancellation: bool,
    /// Produce this direction's egress a far-end **reference** ring for the *opposite* direction's
    /// canceller. True exactly when the opposite direction cancels (it needs the audio this direction
    /// sends toward its party as its reference). For a symmetric leg (both directions cancel) this
    /// equals `echo_cancellation`; it is separate so a future asymmetric single-leg AEC — and the
    /// integration tests — can drive one direction's canceller from the other's reference without the
    /// reverse also cancelling.
    pub produce_echo_reference: bool,
    /// The G.107 codec class of the **ingress** stream (what this direction decodes), for the MOS in
    /// the periodic [`Event::CallQuality`] this direction reports.
    pub ingress_mos_codec: siphon_rtp_hep::mos::Codec,
}

/// Per-direction parameters for a **relay-only** direction (a promoted passthrough leg): just the
/// ingress gate and where to forward verbatim. No codecs — the RTP is copied untouched.
pub struct RelayConfig {
    pub ingress_endpoint: EndpointId,
    pub accepted_source: SourceFilter,
    pub egress_endpoint: EndpointId,
    pub egress_dst: SocketAddr,
    /// This leg's negotiated RFC 4733 telephone-event payload type, if known. Carried so `block DTMF`
    /// can drop the verbatim relay of that PT even on a plain (untranscoded) relay. `None` when the
    /// leg negotiated no telephone-event or its PT could not be resolved — DTMF cannot be gated then.
    pub telephone_event: Option<u8>,
}

/// A companion **RTCP** relay for a *non-muxed* secure-transcode (`SrtpMedia`) leg. RTCP is never
/// transcoded — on the secure side it is SRTCP-decrypted (ingress) / SRTCP-encrypted (egress) against
/// the call's shared [`SecureLeg`] (RFC 3711), and on the plaintext side relayed verbatim; RFC 5761
/// keeps it on its own port here (the muxed case rides the RTP endpoint and is handled inside
/// `Direction::handle`). The `SecureLeg` is the *same* instance the RTP directions share — its SRTCP
/// contexts are distinct from the SRTP ones, so the single-owner actor keeps all crypto state in one
/// place. The RTPBleed source gate is enforced on the RTCP endpoint too.
pub struct RtcpRelay {
    ingress_endpoint: EndpointId,
    accepted_source: SourceFilter,
    egress_endpoint: EndpointId,
    /// The peer's signalled RTCP address. (Dynamic RTCP-follows-RTP latching is a follow-up — RTCP is
    /// gated to the signalled source and forwarded to the signalled address, matching the plain SRTP
    /// bridge's RTCP flows.)
    egress_dst: SocketAddr,
    /// Decrypt SRTCP→RTCP when the ingress faces the secure peer.
    secure_ingress: Option<Arc<Mutex<SecureLeg>>>,
    /// Encrypt RTCP→SRTCP when the egress faces the secure peer.
    secure_egress: Option<Arc<Mutex<SecureLeg>>>,
}

impl RtcpRelay {
    /// A plaintext RTCP relay; layer on `with_secure_ingress` / `with_secure_egress` for the secure side.
    #[must_use]
    pub fn new(
        ingress_endpoint: EndpointId,
        accepted_source: SourceFilter,
        egress_endpoint: EndpointId,
        egress_dst: SocketAddr,
    ) -> Self {
        Self {
            ingress_endpoint,
            accepted_source,
            egress_endpoint,
            egress_dst,
            secure_ingress: None,
            secure_egress: None,
        }
    }

    /// SRTCP-decrypt ingress datagrams against `leg` (the ingress faces the secure peer).
    #[must_use]
    pub fn with_secure_ingress(mut self, leg: Arc<Mutex<SecureLeg>>) -> Self {
        self.secure_ingress = Some(leg);
        self
    }

    /// SRTCP-encrypt egress datagrams against `leg` (the egress faces the secure peer).
    #[must_use]
    pub fn with_secure_egress(mut self, leg: Arc<Mutex<SecureLeg>>) -> Self {
        self.secure_egress = Some(leg);
        self
    }

    /// Relay one RTCP datagram: SRTCP-decrypt (if the ingress is secure) → SRTCP-encrypt (if the
    /// egress is secure — [`SecureLeg`] auto-demuxes RTCP) → transmit toward the peer's RTCP address.
    /// Drops on any (de)crypt failure — never forward garbage RTCP.
    fn relay(&self, data: &[u8], out: &mut Vec<Outbound>) {
        let decrypted;
        let plaintext: &[u8] = if let Some(leg) = &self.secure_ingress {
            let mut buffer = Vec::new();
            let Ok(mut guard) = leg.lock() else { return };
            if guard.unprotect(data, &mut buffer).is_err() {
                return;
            }
            drop(guard);
            decrypted = buffer;
            &decrypted
        } else {
            data
        };
        let encrypted;
        let payload: &[u8] = if let Some(leg) = &self.secure_egress {
            let mut buffer = Vec::new();
            let Ok(mut guard) = leg.lock() else { return };
            if guard.protect(plaintext, &mut buffer).is_err() {
                return;
            }
            drop(guard);
            encrypted = buffer;
            &encrypted
        } else {
            plaintext
        };
        out.push(Outbound {
            endpoint: self.egress_endpoint,
            dst: self.egress_dst,
            data: Bytes::copy_from_slice(payload),
        });
    }
}

impl Direction {
    fn new(config: DirectionConfig) -> Self {
        let ingress_rate = config.decoder.params().sample_rate_hz;
        // The RTP clock the ingress interarrival jitter is measured in (RFC 3550 §6.4.1) — not always
        // the sample rate (G.722 clocks RTP at 8 kHz while sampling 16 kHz; RFC 3551 §4.5.2). Read it
        // before the decoder is moved into the struct.
        let ingress_rtp_clock_rate_hz = config.decoder.rtp_clock_rate_hz();
        let egress_params = config.encoder.params();
        let egress_rate = egress_params.sample_rate_hz;
        // Build a resampler only when the codecs run at different rates (e.g. AMR-WB 16 k → G.711 8 k).
        let resampler = if ingress_rate == egress_rate {
            None
        } else {
            Resampler::new(ingress_rate, egress_rate).ok()
        };
        // Noise suppression runs on the decoded ingress PCM at the ingress codec's native rate; the
        // suppressor only supports 8/16 kHz, so an unsupported rate (e.g. 48 kHz Opus) leaves it off.
        let noise_suppressor = if config.noise_suppression {
            NoiseSuppressor::new(ingress_rate).ok()
        } else {
            None
        };
        // Echo cancellation on this direction's near-end (the decoded uplink), referenced against the
        // opposite direction's egress toward the same party (spec §"Reference/near-end plumbing"). Built
        // at the ingress codec's native rate (what the decoder emits, so its 20 ms frame matches the
        // decoded frame) — see [`build_echo_canceller`] for the backend/default rationale.
        let echo_canceller = if config.echo_cancellation {
            build_echo_canceller(ingress_rate)
        } else {
            None
        };
        // When the *opposite* direction cancels, this direction produces the far-end reference it reads:
        // a preallocated ring of the egress PCM this direction sends toward its party (captured in
        // `emit_pcm`, at the egress codec rate). Bounded (drop-oldest), and only present when the sibling
        // cancels. Sized to a couple of the largest possible frames so a single decoded frame always
        // fits, while an interleave/rate skew is bounded by drop-oldest.
        let echo_reference = if config.produce_echo_reference {
            Some(EchoReference::new(2 * MAX_PCM, egress_rate))
        } else {
            None
        };
        // The egress frame the encoder consumes (and the repacketizer drains) is the encoder's own
        // `frame_samples` — sizing it here from the encoder guarantees the repacketizer always feeds
        // the encoder exactly one frame's worth. A ptime override reaches this via the egress
        // `CodecSpec.ptime_ms` the encoder was built with (sample-based codecs honour it; a frame-based
        // codec such as AMR keeps its native 20 ms frame — the override is inert there by construction).
        // Bound it to the scratch ceiling so an adversarial `a=ptime` can never overflow the fixed
        // egress frame buffer; the timestamp step is recomputed from the same bounded count so drain
        // and RTP clock stay in lock-step.
        let egress_frame_samples = (egress_params.frame_samples() as u32).min(MAX_PCM as u32);
        // RFC 3551 §4.5.2: the synthesized-egress RTP timestamp advances at the codec's RTP clock,
        // which is not always the native sample rate — G.722 clocks RTP at 8 kHz while sampling
        // 16 kHz audio. So the per-packet step is native-samples × RTP-clock ÷ native-rate (= the
        // 8 kHz / 16 kHz halving for G.722; an identity for every other telephony codec).
        let egress_rtp_clock = config.encoder.rtp_clock_rate_hz();
        let egress_timestamp_increment = if egress_rate == 0 {
            egress_frame_samples
        } else {
            ((u64::from(egress_frame_samples) * u64::from(egress_rtp_clock))
                / u64::from(egress_rate)) as u32
        };
        // The repacketizer accumulates egress-domain PCM: one push is at most a decoded+resampled
        // ingress frame (≤ `MAX_PCM`), and it holds < one egress frame of leftover, so `MAX_PCM` of
        // push headroom never reallocates it.
        let repacketizer = Repacketizer::new(egress_frame_samples as usize, MAX_PCM);
        Self {
            ingress_endpoint: config.ingress_endpoint,
            accepted_source: config.accepted_source,
            source_latch: SymmetricLatch::default(),
            egress_endpoint: config.egress_endpoint,
            egress_dst: config.egress_dst,
            relay_only: false,
            raw_tee: Vec::new(),
            decoder: config.decoder,
            encoder: config.encoder,
            resampler,
            noise_suppressor,
            echo_canceller,
            echo_reference,
            egress_sequence: 0,
            egress_timestamp: 0,
            egress_ssrc: config.egress_ssrc,
            egress_payload_type: config.egress_payload_type,
            egress_frame_samples,
            egress_timestamp_increment,
            repacketizer,
            // RFC 3550 §5.1: don't fabricate a talkspurt marker — propagate the sender's. The first
            // egress packet carries the marker only if the ingress stream flagged one.
            pending_marker: false,
            telephone_event_in: config.telephone_event_in,
            telephone_event_out: config.telephone_event_out,
            dtmf: DtmfDetector::new(),
            recorder: config.recorder,
            forks: Vec::new(),
            silenced: false,
            blocked: false,
            dtmf_blocked: false,
            egress_sample_rate: egress_rate,
            injection: None,
            // A comfort-idle single-leg egress is opted in after construction via `enable_comfort_idle`
            // (offer-only local answer / IVR); a normal 2-party direction never idles on comfort noise.
            comfort: None,
            secure_ingress: None,
            secure_egress: None,
            // The ingress interarrival jitter is measured at the ingress codec's RTP clock (RFC 3550
            // §6.4.1), which the decoder exposes — 8 kHz for G.711, 16 kHz for AMR-WB, etc.
            ingress: IngressStats::new(ingress_rtp_clock_rate_hz),
            ingress_mos_codec: config.ingress_mos_codec,
            quality: QualityAggregate::default(),
        }
    }

    /// Build a **relay-only** direction: ingress RTP is forwarded verbatim to the peer (no
    /// decode/encode). Used when a plain passthrough call is promoted to userspace so a SIPREC raw
    /// tee can be attached. The codec fields are unused; a trivial G.711 µ-law pair stands in so the
    /// struct is fully constructed (it is never invoked in this mode).
    fn new_relay(config: RelayConfig) -> Self {
        Self {
            ingress_endpoint: config.ingress_endpoint,
            accepted_source: config.accepted_source,
            source_latch: SymmetricLatch::default(),
            egress_endpoint: config.egress_endpoint,
            egress_dst: config.egress_dst,
            relay_only: true,
            raw_tee: Vec::new(),
            decoder: Box::new(siphon_rtp_codec::g711::G711::ulaw()),
            encoder: Box::new(siphon_rtp_codec::g711::G711::ulaw()),
            resampler: None,
            // A relay-only leg forwards verbatim (never decodes), so there is nothing to suppress or
            // cancel, and it produces no reference for the opposite direction.
            noise_suppressor: None,
            echo_canceller: None,
            echo_reference: None,
            egress_sequence: 0,
            egress_timestamp: 0,
            egress_ssrc: 0,
            egress_payload_type: 0,
            egress_frame_samples: 0,
            egress_timestamp_increment: 0,
            // A relay-only direction forwards RTP verbatim; the repacketizer (frame size 0) never drains.
            repacketizer: Repacketizer::new(0, 0),
            pending_marker: false,
            // Carry the leg's telephone-event PT so `block DTMF` can drop the verbatim relay of it even
            // though this direction never transcodes. `telephone_event_out` stays `None` — a relay-only
            // leg never repacketizes; it drops or forwards the packet whole.
            telephone_event_in: config.telephone_event,
            telephone_event_out: None,
            dtmf: DtmfDetector::new(),
            recorder: None,
            forks: Vec::new(),
            silenced: false,
            blocked: false,
            dtmf_blocked: false,
            egress_sample_rate: 0,
            injection: None,
            // A relay-only direction forwards opaque payloads and never synthesizes egress, so it is
            // never comfort-idle (that is only a decode/re-encode single-leg IVR).
            comfort: None,
            secure_ingress: None,
            secure_egress: None,
            // A relay-only direction never builds a quality report (a promoted passthrough is spawned
            // with no control-event sink, and its quality is reported off the in-kernel relay's RTCP
            // via `Engine::run_rtcp_export`), so its reception estimator stays inert — never fed.
            ingress: IngressStats::new(8000),
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
            // A relay-only direction never samples quality (see above), so the aggregate stays empty.
            quality: QualityAggregate::default(),
        }
    }

    /// Emit the raw-RTP tee for one accepted ingress datagram: copy the **original ingress bytes**
    /// verbatim out each subscriber endpoint toward its SRS (SIPREC raw tee — RFC 7866 §6). No
    /// decode/re-encode, so it carries the source leg's negotiated codec byte-for-byte and works for
    /// any codec the engine cannot encode (e.g. AMR-WB). Applied to RTP, RTCP, and DTMF alike — the
    /// SRS receives exactly what the leg sent.
    fn tee_raw(&self, data: &[u8], out: &mut Vec<Outbound>) {
        for tee in &self.raw_tee {
            out.push(Outbound {
                endpoint: tee.subscriber_endpoint,
                dst: tee.srs_dst,
                data: Bytes::copy_from_slice(data),
            });
        }
    }

    /// Egress packetization in milliseconds, derived from the codec's frame size and rate.
    fn egress_ptime_ms(&self) -> u32 {
        if self.egress_sample_rate == 0 {
            return 20;
        }
        (self.egress_frame_samples * 1000 / self.egress_sample_rate).max(1)
    }

    /// Advance an active injection by one tick, emitting at most one egress packet. Clears the
    /// injection when the prompt / DTMF burst is exhausted, returning [`FinishedPlay`] when a
    /// `play_media` prompt drained naturally (all repeats / the duration cap) so the caller emits the
    /// [`Event::PlayFinished`]. A drained DTMF burst reports nothing (it carries no `play_id`).
    fn tick_injection(&mut self, out: &mut Vec<Outbound>) -> Option<FinishedPlay> {
        let ptime = self.egress_ptime_ms() as usize;
        // Produce this tick's egress step while holding the injection borrow, then act on it after
        // the borrow ends (the encode/packetize path needs `&mut self` again).
        let step = match self.injection.as_mut() {
            Some(Injection::Audio {
                player,
                resampler,
                played_ms,
                ..
            }) => {
                let source_rate = player.sample_rate_hz() as usize;
                let source_frame = (source_rate * ptime / 1000).clamp(1, MAX_PCM);
                let mut source = [0i16; MAX_PCM];
                match player.next_frame(&mut source[..source_frame]) {
                    Some(written) => {
                        // Count this frame's ptime toward the played duration reported on completion.
                        *played_ms += ptime as u64;
                        let frame = match resampler.as_mut() {
                            Some(resampler) => {
                                let mut buffer = Vec::new();
                                resampler.process(&source[..written], &mut buffer);
                                buffer
                            }
                            None => source[..written].to_vec(),
                        };
                        InjectStep::Audio(frame)
                    }
                    None => InjectStep::Exhausted,
                }
            }
            Some(Injection::Dtmf {
                sequence,
                payload_type,
                base_timestamp,
            }) => match sequence.next_step() {
                DtmfStep::Event {
                    payload,
                    timestamp_offset,
                } => InjectStep::Dtmf {
                    bytes: payload.bytes,
                    marker: payload.is_first,
                    payload_type: *payload_type,
                    // Each digit is its own event, offset from the sequence base (RFC 4733 §2.5.1.2).
                    timestamp: base_timestamp.wrapping_add(timestamp_offset),
                },
                DtmfStep::Silence => InjectStep::DtmfSilence,
                DtmfStep::Done => InjectStep::Exhausted,
            },
            None => InjectStep::Idle,
        };

        match step {
            InjectStep::Audio(frame) => {
                self.emit_encoded(&frame, out);
                None
            }
            InjectStep::Dtmf {
                bytes,
                marker,
                payload_type,
                timestamp,
            } => {
                let header = RtpHeader {
                    marker,
                    payload_type,
                    sequence: self.egress_sequence,
                    timestamp,
                    ssrc: self.egress_ssrc,
                };
                let mut buffer = [0u8; MAX_RTP];
                if let Ok(total) = write_packet(&header, &bytes, &mut buffer) {
                    self.push_egress(&buffer[..total], out);
                    self.egress_sequence = self.egress_sequence.wrapping_add(1);
                }
                None
            }
            // Inter-digit gap: emit nothing and keep the injection so the next digit still plays.
            InjectStep::DtmfSilence => None,
            InjectStep::Exhausted => {
                // The prompt / DTMF burst drained naturally. Clear it and, for a `play_media` prompt,
                // report it as `Completed` so the actor emits the matching `Event::PlayFinished`.
                match self.injection.take() {
                    Some(Injection::Audio {
                        play_id, played_ms, ..
                    }) => Some(FinishedPlay {
                        play_id,
                        reason: PlayEndReason::Completed,
                        played_ms,
                    }),
                    _ => None,
                }
            }
            InjectStep::Idle => None,
        }
    }

    /// Encode one PCM frame and append it as an egress packet, advancing the egress counters. Shared
    /// by the prompt-injection path; the transcode path in [`Direction::handle`] inlines the same.
    fn emit_encoded(&mut self, pcm: &[i16], out: &mut Vec<Outbound>) {
        let mut payload = [0u8; MAX_RTP];
        let Ok(payload_len) = self.encoder.encode(pcm, &mut payload) else {
            return;
        };
        let header = RtpHeader {
            marker: false,
            payload_type: self.egress_payload_type,
            sequence: self.egress_sequence,
            timestamp: self.egress_timestamp,
            ssrc: self.egress_ssrc,
        };
        let mut buffer = [0u8; MAX_RTP];
        if let Ok(total) = write_packet(&header, &payload[..payload_len], &mut buffer) {
            self.push_egress(&buffer[..total], out);
            self.egress_sequence = self.egress_sequence.wrapping_add(1);
            self.egress_timestamp = self
                .egress_timestamp
                .wrapping_add(self.egress_timestamp_increment);
        }
    }

    /// Mark this egress direction as a **single-leg** local-answer / IVR leg's comfort-idle egress
    /// (RFC 3389): [`Direction::handle`] stops looping the caller's audio back, and the playout tick
    /// fills the idle egress with comfort noise. `cn_pt` is the negotiated CN payload type when the
    /// caller offered CN (a 1-byte CN packet is sent on it, which the caller's own generator renders),
    /// else `None` for audio-encoded low-level noise on the leg's own codec. The fallback noise
    /// generator runs at the egress codec's native sample rate.
    fn enable_comfort_idle(&mut self, cn_pt: Option<u8>) {
        self.comfort = Some(ComfortNoise {
            cn_pt,
            generator: Cn::new(self.egress_sample_rate, self.egress_ptime_ms() as u8),
        });
    }

    /// One playout tick for this egress direction. An active injection (prompt / DTMF) advances first;
    /// otherwise, on a comfort-idle single-leg leg (`comfort.is_some()`) with `comfort_enabled` (the
    /// `echo` verb off) and not blocked, one comfort-noise frame is emitted so the caller hears a
    /// continuous "nothing to say" stream, never its own audio or dead air. A normal 2-party direction
    /// with no injection emits nothing. Returns the [`FinishedPlay`] a drained prompt reports.
    fn tick_egress(
        &mut self,
        comfort_enabled: bool,
        out: &mut Vec<Outbound>,
    ) -> Option<FinishedPlay> {
        if self.injection.is_some() {
            return self.tick_injection(out);
        }
        if comfort_enabled && !self.blocked && self.comfort.is_some() {
            self.emit_comfort(out);
        }
        None
    }

    /// Emit one idle comfort-noise egress frame (RFC 3389), advancing the egress sequence/timestamp so
    /// the stream stays continuous and a following prompt hands over with no gap or clip. `silence_media`
    /// (hold/mute) emits digital silence instead; otherwise a 1-byte CN packet on the negotiated PT
    /// (the caller renders it) when CN was negotiated, else audio-encoded low-level noise on the codec.
    fn emit_comfort(&mut self, out: &mut Vec<Outbound>) {
        let frame = self.egress_frame_samples as usize;
        // Hold/mute (silence_media): digital silence, still a continuous stream on the audio codec.
        if self.silenced {
            let mut pcm = [0i16; MAX_PCM];
            pcm[..frame].fill(0);
            self.emit_encoded(&pcm[..frame], out);
            return;
        }
        let cn_pt = self.comfort.as_ref().and_then(|comfort| comfort.cn_pt);
        if let Some(payload_type) = cn_pt {
            self.emit_comfort_cn(payload_type, out);
            return;
        }
        // CN was not negotiated: audio-encoded low-level noise on the leg's own codec.
        let mut pcm = [0i16; MAX_PCM];
        if let Some(comfort) = self.comfort.as_mut() {
            comfort
                .generator
                .fill(COMFORT_NOISE_LEVEL_DBOV, &mut pcm[..frame]);
        }
        self.emit_encoded(&pcm[..frame], out);
    }

    /// Emit one RFC 3389 comfort-noise packet (a single `-dBov` level byte, §3.1) on the negotiated CN
    /// payload type, sharing the egress stream's SSRC and advancing its sequence + timestamp — CN
    /// interleaves in the audio SSRC / sequence / timestamp space (§2), so a following prompt continues
    /// the same stream seamlessly. The caller's own generator renders the noise from the level byte.
    fn emit_comfort_cn(&mut self, payload_type: u8, out: &mut Vec<Outbound>) {
        let header = RtpHeader {
            marker: false,
            payload_type,
            sequence: self.egress_sequence,
            timestamp: self.egress_timestamp,
            ssrc: self.egress_ssrc,
        };
        let mut buffer = [0u8; MAX_RTP];
        if let Ok(total) = write_packet(&header, &[COMFORT_NOISE_LEVEL_DBOV], &mut buffer) {
            self.push_egress(&buffer[..total], out);
            self.egress_sequence = self.egress_sequence.wrapping_add(1);
            self.egress_timestamp = self
                .egress_timestamp
                .wrapping_add(self.egress_timestamp_increment);
        }
    }

    /// Build this direction's periodic call-quality event (RFC 3550 §6.4.1 loss/jitter + ITU-T G.107
    /// MOS) from the accumulated ingress statistics, or `None` before any inbound packet (nothing to
    /// report) or on a relay-only direction (its quality is reported off the in-kernel relay's RTCP,
    /// not here). `from_tag` names the leg the quality is measured on; `call_id` correlates it. The
    /// one-way mouth-to-ear delay is `RTT/2` (ITU-T G.107 §7.4) when a reception report has yielded an
    /// RTT, else 0 — the transcode path does not originate its own Sender Reports, so RTT is usually
    /// absent, matching the passive plain-relay QoS export.
    /// This direction's current MOS + the RFC 3550 loss/jitter it was derived from, or `None` before
    /// any inbound packet (nothing to report) or on a relay-only direction (whose quality is reported
    /// off the in-kernel relay's RTCP, not here). Shared by the periodic [`Self::quality_event`] and
    /// the end-of-call [`Self::accumulate_quality`] so both read one consistent computation. The
    /// one-way mouth-to-ear delay is `RTT/2` (ITU-T G.107 §7.4) when a reception report has yielded an
    /// RTT, else 0 — the transcode path does not originate its own Sender Reports, so RTT is usually
    /// absent, matching the passive plain-relay QoS export.
    fn current_quality(&self) -> Option<QualitySample> {
        if self.relay_only || self.ingress.ssrc().is_none() {
            return None;
        }
        let one_way_delay_ms = self.ingress.rtt_ms().map_or(0.0, |rtt_ms| rtt_ms / 2.0);
        let impairments = siphon_rtp_hep::mos::Impairments {
            loss_percent: self.ingress.loss_percent(),
            one_way_delay_ms,
            jitter_ms: self.ingress.jitter_ms(),
        };
        Some(QualitySample {
            mos: siphon_rtp_hep::mos::estimate_mos(self.ingress_mos_codec, impairments),
            jitter_ms: impairments.jitter_ms,
            loss_percent: impairments.loss_percent,
        })
    }

    fn quality_event(&self, call_id: &str, from_tag: &str) -> Option<Event> {
        let sample = self.current_quality()?;
        Some(Event::CallQuality {
            conference_id: None,
            call_id: Some(call_id.to_string()),
            from_tag: from_tag.to_string(),
            jitter_ms: sample.jitter_ms,
            loss_percent: sample.loss_percent,
            mos: sample.mos,
        })
    }

    /// Fold this direction's current quality into its running `QualityAggregate` for the call's CDR.
    /// `at_ms` is the call-relative time of the sample (for the min/max timestamps in the summary). A
    /// no-op before any inbound media, or on a relay-only direction. Driven on the ~5 s quality cadence
    /// — pure arithmetic over accumulated estimates, no per-packet work.
    fn accumulate_quality(&mut self, at_ms: u64) {
        if let Some(sample) = self.current_quality() {
            self.quality
                .record(sample.mos, sample.jitter_ms, sample.loss_percent, at_ms);
        }
    }

    /// Snapshot this direction's end-of-call quality for the CDR — the RFC 3550 reception stats for the
    /// stream it received, plus its running MOS aggregate. All read-only; safe at teardown.
    fn quality_snapshot(&self) -> DirectionQuality {
        DirectionQuality {
            ssrc: self.ingress.ssrc(),
            packets_received: self.ingress.received(),
            packets_expected: self.ingress.expected(),
            packets_lost: self.ingress.cumulative_lost(),
            loss_percent: self.ingress.loss_percent(),
            jitter_ms: self.ingress.jitter_ms(),
            jitter_ms_max: self.quality.jitter_ms_max(),
            loss_percent_max: self.quality.loss_percent_max(),
            rtt_ms: self.ingress.rtt_ms(),
            mos_samples: self.quality.samples(),
            mos_average: self.quality.mos_average(),
            mos_min: self.quality.mos_min(),
            mos_min_at_ms: self.quality.mos_min_at_ms(),
            mos_max: self.quality.mos_max(),
            mos_max_at_ms: self.quality.mos_max_at_ms(),
        }
    }

    /// Transform one accepted datagram for this direction, appending any outbound datagrams and DTMF
    /// events. `source`-gating and latching are the caller's responsibility (it owns both directions).
    /// `arrival_micros` is the datapath's receive-time stamp on the datagram, folded into the ingress
    /// interarrival-jitter estimate (RFC 3550 §6.4.1) that feeds this direction's quality report.
    ///
    /// Returns `Some(ssrc)` when the datagram is an **authentic** RTP media/telephone-event packet
    /// (post SRTP `unprotect` on a secure leg) — the caller then offers it to the reverse direction's
    /// [`SymmetricLatch`] so the reply follows a NAT rebind. Returns `None` for a packet that must
    /// never move the latch: a failed-auth SRTP packet, RTCP, or a malformed/too-short datagram
    /// (docs/security-and-nat.md §4 layer 3 — the reply direction only ever follows an authenticated
    /// stream).
    fn handle(
        &mut self,
        data: &[u8],
        arrival_micros: u64,
        dtmf_meta: DtmfMeta<'_>,
        // The far-end reference for this direction's echo canceller: the *opposite* direction's egress
        // ring (the PCM the engine sent toward this party). Handed in by [`MediaCall::process`] so the
        // cross-direction read needs no `Arc<Mutex>` over leg state. `None` when the leg has no AEC.
        echo_reference: Option<&mut EchoReference>,
        out: &mut Vec<Outbound>,
        events: &mut Vec<Event>,
    ) -> Option<u32> {
        if data.len() < 2 {
            return None;
        }
        // Secure ingress (SDES-SRTP): decrypt before anything else, so the tee / relay / RFC 5761
        // demux / decode all operate on plaintext. SecureLeg auto-demuxes SRTP vs SRTCP. A failed
        // unprotect (bad auth / replay / wrong key) drops the datagram — never forward garbage, and
        // (crucially) returns `None` so an inauthentic packet never moves the reverse latch.
        let decrypted;
        let data: &[u8] = if let Some(leg) = self.secure_ingress.as_ref() {
            let mut plain = Vec::new();
            let Ok(mut guard) = leg.lock() else {
                return None;
            };
            if guard.unprotect(data, &mut plain).is_err() {
                return None;
            }
            drop(guard);
            decrypted = plain;
            &decrypted
        } else {
            data
        };
        // SIPREC raw tee (RFC 7866 §6): copy the original ingress RTP/RTCP/DTMF byte-for-byte to each
        // subscriber's SRS before any transcode/relay. The SRS records the leg's *actual* media in its
        // negotiated codec — independent of hold/mute/transcode on the A↔B path.
        self.tee_raw(data, out);

        // Relay-only (promoted passthrough): forward the ingress RTP verbatim to the peer — no
        // decode/encode. (The raw tee above already copied it to any subscriber, regardless of
        // `blocked`, so the SRS still records a held leg — RFC 7866 §6.) `blocked` suppresses the
        // peer-bound forward so block/unblock still works after promotion.
        if self.relay_only {
            // `block DTMF` on a plain relay: drop the verbatim forward of this leg's RFC 4733
            // telephone-event PT (still detect + emit the event for the controller), but keep RTCP
            // and ordinary RTP flowing. Only the RTP demux applies (RTCP PT 64..=95 is not DTMF).
            if self.dtmf_blocked {
                let packet_type = data[1] & 0x7f; // RTP payload type = low 7 bits of byte 1
                let is_rtcp = (64..=95).contains(&packet_type);
                if !is_rtcp && Some(packet_type) == self.telephone_event_in {
                    // Detect + emit the event so the controller still sees the digit (observability),
                    // then drop the packet — the peer never hears the tone. A malformed telephone-event
                    // still drops (never forward a blocked DTMF PT).
                    if let Ok(parsed) = RtpPacket::parse(data) {
                        if let Ok(Some(event)) =
                            self.dtmf.on_packet(parsed.timestamp, parsed.payload)
                        {
                            events.push(Event::Dtmf {
                                call_id: dtmf_meta.call_id.to_string(),
                                from_tag: dtmf_meta.from_tag.to_string(),
                                to_tag: dtmf_meta.to_tag.map(str::to_string),
                                digit: event.digit.to_string(),
                                duration_ms: u32::from(event.duration) / 8,
                                volume: -i32::from(event.volume),
                                source: None,
                            });
                        }
                    }
                    return None;
                }
            }
            if !self.blocked {
                out.push(Outbound {
                    endpoint: self.egress_endpoint,
                    dst: self.egress_dst,
                    data: Bytes::copy_from_slice(data),
                });
            }
            // A promoted-passthrough leg still latches the reply symmetrically: offer the verbatim
            // packet's SSRC (RTP only; RTCP/non-RTP yields `None` and never moves the latch).
            return rtp_source_ssrc(data);
        }

        // RFC 5761 demux: payload-type byte 64..=95 marks RTCP — relay it (re-encrypting toward a
        // secure egress), untranscoded. RTCP carries no per-stream SSRC at the latch offset, so it
        // never drives the SSRC re-latch (return `None`).
        let packet_type = data[1] & 0x7f;
        if (64..=95).contains(&packet_type) {
            self.push_egress(data, out);
            return None;
        }

        let Ok(parsed) = RtpPacket::parse(data) else {
            return None; // malformed RTP — drop (never forward garbage)
        };
        // The authenticated stream's SSRC (RFC 3550 §5.1) — returned so the caller re-points the
        // reverse direction's egress only for this authentic, SSRC-consistent stream.
        let stream_ssrc = parsed.ssrc;

        // Fold this RTP packet into the per-direction reception statistics (RFC 3550 §6.4.1): SSRC +
        // sequence for the sequence-gap loss, RTP timestamp + arrival for interarrival jitter. Counts
        // audio *and* RFC 4733 telephone-events (they share the audio SSRC + sequence space). O(1),
        // zero-alloc — the ~5 s quality tick reads the accumulated estimate, never the per-packet path.
        self.ingress
            .on_rtp(parsed.ssrc, parsed.sequence, parsed.timestamp);
        self.ingress.observe_arrival(arrival_micros);

        // RFC 4733 telephone-event: extract a DTMF event and repacketize onto the egress stream.
        if Some(parsed.payload_type) == self.telephone_event_in {
            if let Ok(Some(event)) = self.dtmf.on_packet(parsed.timestamp, parsed.payload) {
                events.push(Event::Dtmf {
                    call_id: dtmf_meta.call_id.to_string(),
                    from_tag: dtmf_meta.from_tag.to_string(),
                    to_tag: dtmf_meta.to_tag.map(str::to_string),
                    digit: event.digit.to_string(),
                    // RTP timestamp units are samples at the 8 kHz telephone-event clock (RFC 4733).
                    duration_ms: u32::from(event.duration) / 8,
                    volume: -i32::from(event.volume),
                    source: None,
                });
            }
            // `block DTMF`: still detect + emit the event above (the controller sees the digit), but
            // do not relay it to the peer — the far side never hears the tone. v1 = drop mode.
            // A comfort-idle single-leg leg (`comfort.is_some()`) also never relays: it faces the
            // caller on both directions, so repacketizing the event onto this egress would echo the
            // caller's own DTMF tone back to it. The `Event::Dtmf` above still fired.
            if !self.dtmf_blocked && self.comfort.is_none() {
                self.relay_telephone_event(&parsed, out);
            }
            return Some(stream_ssrc);
        }

        if self.blocked {
            return Some(stream_ssrc);
        }
        // While a prompt / DTMF burst plays toward this party, suppress the transcoded audio so the
        // injection is heard cleanly (the playout clock drives the egress instead — see `tick_injection`).
        if self.injection.is_some() {
            return Some(stream_ssrc);
        }

        // Decode → (noise suppression) → record → (silence) → resample → encode → transmit.
        let mut decoded = [0i16; MAX_PCM];
        let Ok(samples) = self.decoder.decode(parsed.payload, &mut decoded) else {
            return Some(stream_ssrc); // authentic stream member, just undecodable — still latches
        };
        // Suppress noise in place first, so the recorder, SIPREC forks, and the peer all receive the
        // cleaned audio. Streaming/WOLA — one ingress frame in, the same count out (delayed).
        if let Some(suppressor) = self.noise_suppressor.as_mut() {
            suppressor.process(&mut decoded[..samples]);
        }
        // Post-decode / post-NS echo cancellation, in the ingress codec's native-rate domain (pre-
        // resample, pre-encode). The far-end reference is the *opposite* direction's egress toward this
        // party — the audio the engine sent this party, whose echo returns on this uplink — handed in as
        // `echo_reference`. Reference and near-end share the party's negotiated codec rate by
        // construction (offer/answer: a party sends and receives in one codec), so no rate alignment is
        // needed; `cancel` echo-subtracts in place with zero per-frame heap. A partially-filled
        // reference frame is zero-padded by `read_into` (a silent far-end ⇒ nothing to cancel).
        if let (Some(canceller), Some(reference)) = (self.echo_canceller.as_mut(), echo_reference) {
            debug_assert_eq!(
                reference.sample_rate_hz,
                canceller.sample_rate_hz(),
                "far-end reference and near-end must share the party's codec rate"
            );
            let mut far_end = [0i16; MAX_PCM];
            reference.read_into(&mut far_end[..samples]);
            canceller.cancel(&mut decoded[..samples], &far_end[..samples]);
        }
        let decoded = &decoded[..samples];
        if let Some(recorder) = self.recorder.as_mut() {
            recorder.write_pcm(decoded);
        }
        // SIPREC / monitor fork: re-encode the decoded ingress PCM toward each subscriber. Fed the
        // same raw decoded audio as the recorder (pre-silence, pre-resample) so a fork captures what
        // the leg actually said, independent of hold/mute state on the A↔B path (RFC 7866 §6). A full
        // or disconnected subscriber drops the frame inside the sink — it never stalls the transcode.
        for fork in &mut self.forks {
            fork.write_pcm(decoded);
        }

        // Single-leg local-answer / IVR leg (RFC 3264 §6.1 single m-line): both directions face the
        // caller, so re-encoding the decoded ingress back out this egress would loop the caller's own
        // audio to it (self-echo). The decode above still fed the recorder / SIPREC forks / DTMF
        // detector / reception stats, and the stream still latches (`Some(stream_ssrc)`); the idle
        // egress is a continuous comfort-noise stream driven by the playout tick instead (see
        // `tick_egress`). A player overrides it; the `echo` verb reflects via `echo_into`.
        if self.comfort.is_some() {
            return Some(stream_ssrc);
        }

        let silence;
        let pre_resample: &[i16] = if self.silenced {
            silence = vec![0i16; samples];
            &silence
        } else {
            decoded
        };

        let resampled;
        let egress_pcm: &[i16] = match self.resampler.as_mut() {
            Some(resampler) => {
                let mut buffer = Vec::new();
                resampler.process(pre_resample, &mut buffer);
                resampled = buffer;
                &resampled
            }
            None => pre_resample,
        };

        // Re-frame to the egress ptime: accumulate in the egress sample domain (post-resample) and
        // emit one RTP packet per full egress frame. Resample **then** accumulate — the resampler is
        // stateful (holds filter history across frames) so it must see the continuous per-ingress-frame
        // stream, and accumulating in the egress domain makes the drain quantum exactly the encoder's
        // frame size.
        self.repacketize(egress_pcm, parsed.marker, out);
        Some(stream_ssrc)
    }

    /// Re-frame decoded egress-domain PCM to this direction's egress `ptime` and emit one RTP packet
    /// per full egress frame. The accumulator (preallocated) buffers a partial frame across ingress
    /// packets, so a small ingress frame waits for a full egress frame and a large one emits several —
    /// each with sequence +1 (RFC 3550 §5.1) and timestamp +`egress_timestamp_increment` (in the RTP
    /// clock, RFC 3551 §4.5.2), advanced by [`Direction::emit_pcm`].
    fn repacketize(&mut self, egress_pcm: &[i16], ingress_marker: bool, out: &mut Vec<Outbound>) {
        // RFC 3550 §5.1: the marker flags the first packet of a talkspurt. Carry the sender's talkspurt
        // boundary to the *first* egress packet that follows (repacketization means one ingress packet
        // maps to zero-or-many egress packets), rather than stamping every egress packet with it.
        if ingress_marker {
            self.pending_marker = true;
        }
        // No egress framing (degenerate frame size 0): emit the chunk as one packet, unchanged.
        if self.repacketizer.frame_samples() == 0 {
            let marker = std::mem::take(&mut self.pending_marker);
            self.emit_pcm(egress_pcm, marker, out);
            return;
        }
        self.repacketizer.push(egress_pcm);
        // `egress_frame_samples` is bounded to `MAX_PCM` in `Direction::new`, so one frame always fits.
        let mut frame = [0i16; MAX_PCM];
        while let Some(count) = self.repacketizer.next_frame(&mut frame) {
            let marker = std::mem::take(&mut self.pending_marker);
            self.emit_pcm(&frame[..count], marker, out);
        }
    }

    /// Append one egress datagram toward this direction's peer, encrypting it (SRTP/SRTCP, auto-
    /// demuxed by [`SecureLeg`]) first when the egress faces a secure peer. `plaintext` is a complete
    /// RTP or RTCP packet; on a plaintext leg it is forwarded verbatim. A failed protect drops it.
    fn push_egress(&self, plaintext: &[u8], out: &mut Vec<Outbound>) {
        let data = if let Some(leg) = self.secure_egress.as_ref() {
            let mut sealed = Vec::new();
            let Ok(mut guard) = leg.lock() else { return };
            if guard.protect(plaintext, &mut sealed).is_err() {
                return;
            }
            drop(guard);
            Bytes::from(sealed)
        } else {
            Bytes::copy_from_slice(plaintext)
        };
        out.push(Outbound {
            endpoint: self.egress_endpoint,
            dst: self.egress_dst,
            data,
        });
    }

    /// Encode one frame of egress PCM and append the resulting RTP packet to `out`, advancing this
    /// direction's egress sequence/timestamp. Shared by the transcode path ([`Direction::handle`])
    /// and the echo path ([`Direction::echo_into`]); `pcm` must already be at the egress codec's rate.
    fn emit_pcm(&mut self, pcm: &[i16], marker: bool, out: &mut Vec<Outbound>) {
        // Capture the egress PCM as the far-end reference for the *opposite* direction's echo canceller
        // (present iff that direction cancels): this is exactly what the engine sends toward this party,
        // whose echo the reverse direction cancels off that party's uplink. Whatever the egress source
        // — transcode, injected prompt, or echo-test reflect — it is what the party hears.
        if let Some(reference) = self.echo_reference.as_mut() {
            reference.push(pcm);
        }
        let mut payload = [0u8; MAX_RTP];
        let Ok(payload_len) = self.encoder.encode(pcm, &mut payload) else {
            return;
        };
        let header = RtpHeader {
            marker,
            payload_type: self.egress_payload_type,
            sequence: self.egress_sequence,
            timestamp: self.egress_timestamp,
            ssrc: self.egress_ssrc,
        };
        let mut buffer = [0u8; MAX_RTP];
        if let Ok(total) = write_packet(&header, &payload[..payload_len], &mut buffer) {
            self.push_egress(&buffer[..total], out);
            self.egress_sequence = self.egress_sequence.wrapping_add(1);
            self.egress_timestamp = self
                .egress_timestamp
                .wrapping_add(self.egress_timestamp_increment);
        }
    }

    /// Echo this direction's ingress audio straight back to the party that sent it (the classic echo
    /// test). `self` decodes the ingress (its decoder faces the sending party); `egress` is the
    /// direction whose egress faces that same party, used to re-encode + transmit the audio home.
    ///
    /// RFC 4733 telephone-events are still detected and emitted as [`Event::Dtmf`] (so the SBC can end
    /// the test on `#`) but are not echoed; RTCP is ignored. Both directions carry the party's single
    /// negotiated codec, so no resampling is needed — the decoded PCM feeds the egress encoder directly.
    ///
    /// Returns `Some(ssrc)` for an authentic RTP packet (the caller offers it to the reverse latch,
    /// exactly as [`Direction::handle`]) and `None` for RTCP / malformed input.
    fn echo_into(
        &mut self,
        egress: &mut Direction,
        data: &[u8],
        dtmf_meta: DtmfMeta<'_>,
        out: &mut Vec<Outbound>,
        events: &mut Vec<Event>,
    ) -> Option<u32> {
        if data.len() < 2 {
            return None;
        }
        // RFC 5761 demux: ignore RTCP on the echo path (nothing to reflect).
        let packet_type = data[1] & 0x7f;
        if (64..=95).contains(&packet_type) {
            return None;
        }
        let Ok(parsed) = RtpPacket::parse(data) else {
            return None;
        };
        let stream_ssrc = parsed.ssrc;
        // Detect DTMF so the caller can end the echo test on a digit; do not echo the tone itself.
        if Some(parsed.payload_type) == self.telephone_event_in {
            if let Ok(Some(event)) = self.dtmf.on_packet(parsed.timestamp, parsed.payload) {
                events.push(Event::Dtmf {
                    call_id: dtmf_meta.call_id.to_string(),
                    from_tag: dtmf_meta.from_tag.to_string(),
                    to_tag: dtmf_meta.to_tag.map(str::to_string),
                    digit: event.digit.to_string(),
                    duration_ms: u32::from(event.duration) / 8,
                    volume: -i32::from(event.volume),
                    source: None,
                });
            }
            return Some(stream_ssrc);
        }
        let mut decoded = [0i16; MAX_PCM];
        let Ok(samples) = self.decoder.decode(parsed.payload, &mut decoded) else {
            return Some(stream_ssrc);
        };
        egress.emit_pcm(&decoded[..samples], parsed.marker, out);
        Some(stream_ssrc)
    }

    /// Repacketize a telephone-event onto the egress stream: keep the event's RTP timestamp (RFC 4733
    /// holds it constant across the event), but stamp the engine's egress SSRC and sequence so the
    /// receiving party sees a coherent stream. The egress telephone-event payload type is used.
    fn relay_telephone_event(&mut self, parsed: &RtpPacket<'_>, out: &mut Vec<Outbound>) {
        let Some(payload_type) = self.telephone_event_out else {
            return; // the receiving party did not negotiate telephone-event — drop (event already emitted)
        };
        let header = RtpHeader {
            marker: parsed.marker,
            payload_type,
            sequence: self.egress_sequence,
            timestamp: parsed.timestamp,
            ssrc: self.egress_ssrc,
        };
        let mut buffer = [0u8; MAX_RTP];
        if let Ok(total) = write_packet(&header, parsed.payload, &mut buffer) {
            self.push_egress(&buffer[..total], out);
            self.egress_sequence = self.egress_sequence.wrapping_add(1);
        }
    }
}

/// Metadata threaded into [`Direction::handle`] so an extracted DTMF event names its call/leg.
struct DtmfMeta<'a> {
    call_id: &'a str,
    from_tag: &'a str,
    to_tag: Option<&'a str>,
}

/// A media-processing call: two directions plus the call identity for event correlation.
///
/// `process` is pure and synchronous — feed it a redirected datagram, collect the datagrams to send
/// and DTMF events to emit. The async actor (`run_media_call`) wraps it with the datapath I/O.
pub struct MediaCall {
    call_id: String,
    from_tag: String,
    to_tag: Option<String>,
    /// Media from party A toward party B.
    a_to_b: Direction,
    /// Media from party B toward party A.
    b_to_a: Direction,
    /// Latch each party's observed source so the reverse direction replies symmetrically (RFC 3550).
    latch: bool,
    /// Echo-test mode: reflect each party's ingress audio straight back to itself instead of
    /// forwarding it to the peer ([`MediaControl::Echo`]). Off for normal calls.
    echo: bool,
    /// Where to write the recorded WAV on teardown, when recording.
    record_path: Option<String>,
    /// Companion (non-muxed) RTCP relays, for a secure-transcode leg whose RTCP rides its own port
    /// (RFC 5761). Empty for a muxed call — muxed RTCP is (de)crypted/relayed inside [`Direction::handle`].
    rtcp: Vec<RtcpRelay>,
    /// An active raw-RTP pcap capture (`MediaControl::StartRecording`). Each accepted ingress datagram
    /// on either RTP leg is copied byte-for-byte to the sink; the engine owns the drain task that
    /// frames + streams it to disk. `None` unless recording — the actor's per-packet cost is one
    /// bounded `try_send` per captured packet, and dropping under backpressure keeps recording from
    /// ever stalling the media path.
    capture: Option<PcapCapture>,
}

/// The sink + per-leg engine-local addresses for an active raw-RTP pcap capture. The local address
/// is the synthetic destination stamped in the captured frame's 5-tuple (the engine socket the
/// datagram arrived on), so the pcap dissects as `peer → engine`.
pub struct PcapCapture {
    /// The bounded channel the accepted ingress datagrams are streamed to (drained by the engine).
    pub sender: flume::Sender<CapturedPacket>,
    /// Engine-local address of leg A's ingress endpoint (capture destination for A's packets).
    pub a_local: SocketAddr,
    /// Engine-local address of leg B's ingress endpoint (capture destination for B's packets).
    pub b_local: SocketAddr,
}

impl MediaCall {
    /// Install the call's shared SDES-SRTP leg for a **secure + transcoding** topology: the *far*
    /// party (B) is the secure (`RTP/SAVP`) peer, A is plaintext. The A→B egress is encrypted and the
    /// B→A ingress is decrypted against the one shared [`SecureLeg`] (single-owner actor ⇒ the `Mutex`
    /// is uncontended). RTCP rides the same leg (SecureLeg auto-demuxes SRTCP).
    #[must_use]
    pub fn with_far_secure_leg(mut self, leg: Arc<Mutex<SecureLeg>>) -> Self {
        self.a_to_b.secure_egress = Some(leg.clone());
        self.b_to_a.secure_ingress = Some(leg);
        self
    }

    /// The call's shared SDES-SRTP leg, when this is a secure-transcode (`SrtpMedia`) call — so the
    /// registry can retain a handle to it after the actor takes ownership of the `MediaCall`, and read
    /// the leg's SRTP rollover for an HA checkpoint (RFC 3711 §3.3.1). `None` for a plaintext transcode
    /// / relay call (no secure leg). The `a_to_b` egress and `b_to_a` ingress share the one `Arc` (set
    /// together by [`MediaCall::with_far_secure_leg`]), so returning the A→B egress handle is enough.
    #[must_use]
    pub fn far_secure_leg(&self) -> Option<Arc<Mutex<SecureLeg>>> {
        self.a_to_b.secure_egress.clone()
    }

    /// Build a call from its two directions and identity.
    #[must_use]
    pub fn new(
        call_id: impl Into<String>,
        from_tag: impl Into<String>,
        to_tag: Option<String>,
        a_to_b: DirectionConfig,
        b_to_a: DirectionConfig,
        latch: bool,
        record_path: Option<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            from_tag: from_tag.into(),
            to_tag,
            a_to_b: Direction::new(a_to_b),
            b_to_a: Direction::new(b_to_a),
            latch,
            echo: false,
            record_path,
            rtcp: Vec::new(),
            capture: None,
        }
    }

    /// Attach companion (non-muxed) RTCP relays for a secure-transcode leg — the RTCP endpoints whose
    /// datagrams the actor SRTCP-(de)crypts and forwards without transcoding (RFC 5761 keeps RTCP on
    /// its own port). Their ingress endpoints must be redirected to this actor and routed in the
    /// [`MediaRegistry`] (see [`MediaCall::rtcp_endpoints`]).
    #[must_use]
    pub fn with_rtcp_relays(mut self, relays: Vec<RtcpRelay>) -> Self {
        self.rtcp = relays;
        self
    }

    /// The companion-RTCP endpoints this call routes (empty unless [`MediaCall::with_rtcp_relays`]),
    /// so the registry can direct their redirected datagrams to this actor.
    #[must_use]
    pub fn rtcp_endpoints(&self) -> Vec<EndpointId> {
        self.rtcp
            .iter()
            .map(|relay| relay.ingress_endpoint)
            .collect()
    }

    /// Build a **relay-only** call: both directions forward their ingress RTP verbatim to the peer
    /// (no transcode). Used when a plain passthrough relay is promoted to userspace so a SIPREC raw
    /// tee can be attached to a leg (the in-kernel `Forward` fast path has no userspace tap). The
    /// per-direction source gate + symmetric latch are re-enforced exactly as the `Forward` rule did
    /// (RTPBleed defence — the Redirect path bypasses the datapath gate, docs/security-and-nat.md §4).
    #[must_use]
    pub fn new_relay(
        call_id: impl Into<String>,
        from_tag: impl Into<String>,
        to_tag: Option<String>,
        a_to_b: RelayConfig,
        b_to_a: RelayConfig,
        latch: bool,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            from_tag: from_tag.into(),
            to_tag,
            a_to_b: Direction::new_relay(a_to_b),
            b_to_a: Direction::new_relay(b_to_a),
            latch,
            echo: false,
            record_path: None,
            rtcp: Vec::new(),
            capture: None,
        }
    }

    /// The endpoints this call owns (for registry routing and teardown).
    #[must_use]
    pub fn endpoints(&self) -> [EndpointId; 2] {
        [self.a_to_b.ingress_endpoint, self.b_to_a.ingress_endpoint]
    }

    /// Whether this is a relay-only call (a promoted passthrough leg, no transcode). Lets the engine
    /// keep its media-only guards (silence / play / DTMF require a transcoding call) correct after a
    /// passthrough call is promoted for SIPREC.
    #[must_use]
    pub fn is_relay_only(&self) -> bool {
        self.a_to_b.relay_only && self.b_to_a.relay_only
    }

    /// Process one redirected datagram, gating its source and latching the reverse direction's
    /// destination, then transcoding/relaying it. Returns `true` when the packet passed its source gate
    /// and was acted on — the caller stamps media-activity for the timeout sweep only on that (a spoofed
    /// spray dropped by the gate must never keep an idle path alive, mirroring the conference actor).
    pub fn process(
        &mut self,
        packet: &RxPacket,
        out: &mut Vec<Outbound>,
        events: &mut Vec<Event>,
    ) -> bool {
        let meta = DtmfMeta {
            call_id: &self.call_id,
            from_tag: &self.from_tag,
            to_tag: self.to_tag.as_deref(),
        };
        if packet.endpoint == self.a_to_b.ingress_endpoint {
            // Party A's media: gate A's source; the B→A direction now knows where to reply to A.
            if !self.a_to_b.accepted_source.accepts(packet.source.ip()) {
                tracing::debug!(source = %packet.source, "media-pipeline dropped packet from unsignalled source");
                return false;
            }
            // Raw-RTP pcap capture (accepted A→B ingress, post source-gate, before any transcode).
            self.capture_ingress(true, packet.source, packet.arrival, &packet.data);
            let latch_ssrc = if self.echo {
                // Echo A back to A: decode on a_to_b (faces A), re-encode on b_to_a (egress faces A).
                self.a_to_b
                    .echo_into(&mut self.b_to_a, &packet.data, meta, out, events)
            } else {
                // Cancel A's uplink echo against what the engine last sent *toward* A — the `b_to_a`
                // egress reference ring (§"Reference/near-end plumbing"). Disjoint field borrows
                // (`a_to_b` receiver, `b_to_a` reference) hand it across with no lock, as `echo_into`.
                let latch_ssrc = self.a_to_b.handle(
                    &packet.data,
                    packet.arrival,
                    meta,
                    self.b_to_a.echo_reference.as_mut(),
                    out,
                    events,
                );
                // RFC 4867 §4.3.1: A's Codec Mode Request steers the mode of the stream sent *back* to
                // A (the b_to_a egress encoder). No-op for a fixed-rate codec / no request.
                if let Some(mode) = self.a_to_b.decoder.last_mode_request() {
                    self.b_to_a.encoder.request_mode(mode);
                }
                latch_ssrc
            };
            // Symmetric-RTP latch (docs/security-and-nat.md §4 layer 3; RFC 3550 §8): re-point the
            // B→A reply to A's observed source only for an **authentic**, SSRC-consistent stream —
            // after SRTP auth (a forged packet returned `None` above) and never for a new source
            // carrying a different SSRC (a hijack). The exact-source default path is unchanged: the
            // gate above already pinned the source to A's signalled IP.
            if self.latch {
                if let Some(ssrc) = latch_ssrc {
                    if let Some(dst) = self.a_to_b.source_latch.observe(packet.source, ssrc) {
                        self.b_to_a.egress_dst = dst;
                    }
                }
            }
            // Passive per-leg RTT (RFC 3550 §6.4.1) from the plaintext RTCP this leg relays: the
            // engine↔A round trip feeds A's one-way delay so its MOS gains the delay term. A secure
            // (SRTCP) leg's RTCP is opaque here, so its RTT stays absent (the CDR marks it honestly).
            if self.a_to_b.secure_ingress.is_none() && is_rtcp_datagram(&packet.data) {
                self.observe_rtcp_rtt(true, &packet.data, packet.arrival);
            }
            true
        } else if packet.endpoint == self.b_to_a.ingress_endpoint {
            if !self.b_to_a.accepted_source.accepts(packet.source.ip()) {
                tracing::debug!(source = %packet.source, "media-pipeline dropped packet from unsignalled source");
                return false;
            }
            // Raw-RTP pcap capture (accepted B→A ingress, post source-gate, before any transcode).
            self.capture_ingress(false, packet.source, packet.arrival, &packet.data);
            let latch_ssrc = if self.echo {
                self.b_to_a
                    .echo_into(&mut self.a_to_b, &packet.data, meta, out, events)
            } else {
                // Symmetric: cancel B's uplink echo against the `a_to_b` egress reference (what the
                // engine last sent toward B).
                let latch_ssrc = self.b_to_a.handle(
                    &packet.data,
                    packet.arrival,
                    meta,
                    self.a_to_b.echo_reference.as_mut(),
                    out,
                    events,
                );
                // Symmetric: B's CMR steers the a_to_b egress encoder (the stream sent back to B).
                if let Some(mode) = self.b_to_a.decoder.last_mode_request() {
                    self.a_to_b.encoder.request_mode(mode);
                }
                latch_ssrc
            };
            // Symmetric-RTP latch for the A→B reply, mirroring the A branch: only an authentic,
            // SSRC-consistent B stream re-points `a_to_b.egress_dst` (docs/security-and-nat.md §4
            // layer 3; RFC 3550 §8).
            if self.latch {
                if let Some(ssrc) = latch_ssrc {
                    if let Some(dst) = self.b_to_a.source_latch.observe(packet.source, ssrc) {
                        self.a_to_b.egress_dst = dst;
                    }
                }
            }
            // Passive per-leg RTT, mirrored for the B leg (engine↔B round trip).
            if self.b_to_a.secure_ingress.is_none() && is_rtcp_datagram(&packet.data) {
                self.observe_rtcp_rtt(false, &packet.data, packet.arrival);
            }
            true
        } else if let Some(relay) = self
            .rtcp
            .iter()
            .find(|relay| relay.ingress_endpoint == packet.endpoint)
        {
            // Companion (non-muxed) RTCP on a secure-transcode leg: gate the source (RTPBleed) then
            // SRTCP-(de)crypt and relay it untranscoded toward the peer's RTCP port.
            if !relay.accepted_source.accepts(packet.source.ip()) {
                tracing::debug!(source = %packet.source, "media-pipeline dropped RTCP from unsignalled source");
                return false;
            }
            relay.relay(&packet.data, out);
            true
        } else {
            false
        }
    }

    /// Passively derive per-leg round-trip time from the plaintext RTCP the transcode path relays
    /// (RFC 3550 §6.4.1), so a relay/transcode call's MOS gains its one-way-delay term (the CDR marks
    /// it `mos_basis=full`) instead of loss+jitter only. `from_a` is `true` for party A's inbound RTCP
    /// (it arrived on the `a_to_b` leg), `false` for party B's.
    ///
    /// A round trip spans both legs, so this lives on the `MediaCall` (which owns both directions), not
    /// a single [`Direction`]. The engine↔party RTT for one party is reconstructed from the RTCP it
    /// relays *to and from* that party:
    ///
    /// - A **Sender Report** carries the NTP timestamp the *receiving* party will echo back as `LSR` in
    ///   its next reception report. When it arrives (about to be relayed to the peer), record it against
    ///   the **peer's** ingress leg — the leg that will later process that echo — keyed by NTP-middle-32
    ///   ([`IngressStats::record_sent_report`]), with the relay time ≈ its arrival.
    /// - A **reception block** from a party (in its SR or RR) reports on the engine's egress stream
    ///   toward that party (the *opposite* leg's egress SSRC) and echoes `LSR`/`DLSR`. Matching it
    ///   against the recorded relay time yields the engine↔party RTT
    ///   ([`IngressStats::record_reception_report`]), stored on that party's own ingress leg.
    ///
    /// `arrival_micros` is the datapath's logical receive time, so the RTT stays deterministic. Only
    /// the plaintext relay path is observed — a secure (SRTCP) leg's RTCP is opaque here (the plaintext
    /// exists only inside [`Direction::handle`]), so its RTT stays absent, which the CDR reports honestly.
    fn observe_rtcp_rtt(&mut self, from_a: bool, data: &[u8], arrival_micros: u64) {
        let Ok(compound) = siphon_rtp_media::rtcp::parse_compound(data) else {
            return;
        };
        for packet in compound {
            let blocks = match packet {
                siphon_rtp_media::rtcp::RtcpPacket::SenderReport(report) => {
                    // The SR's NTP is what the *peer* echoes as LSR — record it on the peer's ingress
                    // leg (which processes that echo) as the engine's relay time for this SR.
                    if from_a {
                        self.b_to_a
                            .ingress
                            .record_sent_report(report.ntp_timestamp, arrival_micros);
                    } else {
                        self.a_to_b
                            .ingress
                            .record_sent_report(report.ntp_timestamp, arrival_micros);
                    }
                    report.reports
                }
                siphon_rtp_media::rtcp::RtcpPacket::ReceiverReport(report) => report.reports,
                siphon_rtp_media::rtcp::RtcpPacket::Other { .. } => continue,
            };
            // A reception block from this party reports on the engine's egress toward it (the *opposite*
            // leg's egress SSRC); matching its echoed LSR/DLSR yields the engine↔party RTT, stored on
            // this party's own ingress leg.
            for block in &blocks {
                if from_a {
                    let egress_ssrc = self.b_to_a.egress_ssrc;
                    self.a_to_b
                        .ingress
                        .record_reception_report(egress_ssrc, block, arrival_micros);
                } else {
                    let egress_ssrc = self.a_to_b.egress_ssrc;
                    self.b_to_a
                        .ingress
                        .record_reception_report(egress_ssrc, block, arrival_micros);
                }
            }
        }
    }

    /// Enable or disable echo-test mode (`Command::Echo`): when on, each party's ingress audio is
    /// reflected straight back to itself instead of being forwarded to the peer.
    pub fn set_echo(&mut self, echo: bool) {
        self.echo = echo;
    }

    /// Toggle comfort-silence on both egress directions (`Command::SilenceMedia`).
    pub fn set_silenced(&mut self, silenced: bool) {
        self.a_to_b.silenced = silenced;
        self.b_to_a.silenced = silenced;
    }

    /// Toggle full egress blocking on both directions (`Command::BlockMedia`).
    pub fn set_blocked(&mut self, blocked: bool) {
        self.a_to_b.blocked = blocked;
        self.b_to_a.blocked = blocked;
    }

    /// Block (`blocked = true`) or resume (`false`) relaying one leg's RFC 4733 telephone-events
    /// (`Command::BlockDtmf`). `source_a` selects the blocked source leg: `true` ⇒ leg A. It is set on
    /// the leg's **ingress** direction (leg A's telephone-events arrive on `a_to_b`), so A's DTMF is
    /// dropped toward B while B's is unaffected. Detection still fires — the controller sees the digit.
    pub fn set_dtmf_blocked(&mut self, source_a: bool, blocked: bool) {
        self.ingress_direction(source_a).dtmf_blocked = blocked;
    }

    /// Begin a raw-RTP pcap capture (`MediaControl::StartRecording`): every accepted ingress datagram
    /// on either leg is copied byte-for-byte to the sink. Replacing an existing capture drops the old
    /// sink, closing its channel so the engine's drain task finalizes that file.
    pub fn start_recording(&mut self, capture: PcapCapture) {
        self.capture = Some(capture);
    }

    /// Stop a raw-RTP pcap capture (`MediaControl::StopRecording`): drop the sink so the engine's
    /// drain task sees the channel close and finalizes the file. A no-op if not recording.
    pub fn stop_recording(&mut self) {
        self.capture = None;
    }

    /// Whether a raw-RTP pcap capture is active (test/observability helper).
    #[must_use]
    pub fn is_recording(&self) -> bool {
        self.capture.is_some()
    }

    /// Copy one accepted ingress datagram to the pcap sink, if recording. `leg_a` selects the capture
    /// destination (leg A's or leg B's engine-local address). Bounded, drop-on-full: a recording is
    /// best-effort and must never backpressure the media path.
    fn capture_ingress(&self, leg_a: bool, source: SocketAddr, arrival: u64, data: &[u8]) {
        let Some(capture) = &self.capture else {
            return;
        };
        let destination = if leg_a {
            capture.a_local
        } else {
            capture.b_local
        };
        let packet =
            CapturedPacket::new(source, destination, Bytes::copy_from_slice(data), arrival);
        if capture.sender.try_send(packet).is_err() {
            tracing::debug!("pcap capture dropped a packet (sink full or closed)");
        }
    }

    /// The egress direction that plays toward party A (`toward_a = true`) or party B.
    fn direction_toward(&mut self, toward_a: bool) -> &mut Direction {
        if toward_a {
            &mut self.b_to_a // its egress socket faces A
        } else {
            &mut self.a_to_b // its egress socket faces B
        }
    }

    /// Start a prompt / announcement toward a party (`Command::PlayMedia`). The player carries the
    /// source-rate PCM; a resampler is built when it differs from the egress codec rate. `play_id` is
    /// the accept's playback id, carried on the eventual [`Event::PlayFinished`]. If a prior prompt is
    /// still playing on this direction it is superseded now — a `PlayFinished{Superseded}` for its
    /// `play_id` is pushed onto `events`, so a controller awaiting the old prompt resolves (not
    /// completed) rather than hanging.
    pub fn start_play_audio(
        &mut self,
        toward_a: bool,
        player: PcmPlayer,
        play_id: u64,
        events: &mut Vec<Event>,
    ) {
        let superseded = {
            let direction = self.direction_toward(toward_a);
            // Taking the prior injection stops any in-flight prompt / DTMF on this direction; only a
            // prompt (with a `play_id`) is reported, as `Superseded`.
            let superseded = Self::take_finished_play(direction, PlayEndReason::Superseded);
            let resampler = if player.sample_rate_hz() == direction.egress_sample_rate {
                None
            } else {
                Resampler::new(player.sample_rate_hz(), direction.egress_sample_rate).ok()
            };
            direction.injection = Some(Injection::Audio {
                player,
                resampler,
                play_id,
                played_ms: 0,
            });
            superseded
        };
        if let Some(finished) = superseded {
            events.push(self.play_finished_event(finished));
        }
    }

    /// Start a DTMF sequence toward a party (`Command::PlayDtmf`): `digits` is played as one RFC 4733
    /// event per digit, each `duration_ms` long, separated by `pause_ms` of silence. Returns `false`
    /// if the party has no negotiated telephone-event payload type to carry it, or `digits` is empty /
    /// carries a non-DTMF character (the engine validates the code, so this is a defensive guard).
    pub fn start_play_dtmf(
        &mut self,
        toward_a: bool,
        digits: &str,
        duration_ms: u32,
        volume: u8,
        pause_ms: u32,
    ) -> bool {
        let direction = self.direction_toward(toward_a);
        let Some(payload_type) = direction.telephone_event_out else {
            return false;
        };
        let clock_rate = direction.egress_sample_rate;
        let ptime = direction.egress_ptime_ms() as u8;
        let Some(sequence) =
            DtmfSequence::new(digits, duration_ms, volume, clock_rate, ptime, pause_ms)
        else {
            return false;
        };
        let base_timestamp = direction.egress_timestamp;
        direction.injection = Some(Injection::Dtmf {
            sequence,
            payload_type,
            base_timestamp,
        });
        true
    }

    /// Stop any prompt / DTMF injection on both directions (`Command::StopMedia`). A `play_media`
    /// prompt in flight is reported as `PlayFinished{Stopped}` on `events` — an explicit stop is a
    /// valid end of the playout, so a controller awaiting the prompt resolves (not completed) rather
    /// than hanging.
    pub fn stop_play(&mut self, events: &mut Vec<Event>) {
        self.end_all_plays(PlayEndReason::Stopped, events);
    }

    /// Report every in-flight `play_media` prompt as ended by the leg's teardown
    /// (`PlayFinished{Error}`), draining the injections. Called when the actor exits (leg torn down /
    /// mailbox closed) so a controller awaiting a prompt that will never finish is released.
    pub fn finish_pending_plays(&mut self, events: &mut Vec<Event>) {
        self.end_all_plays(PlayEndReason::Error, events);
    }

    /// Take (stop) any injection on both directions, emitting a `PlayFinished{reason}` for each that
    /// was a `play_media` prompt. Shared by [`Self::stop_play`] and [`Self::finish_pending_plays`].
    fn end_all_plays(&mut self, reason: PlayEndReason, events: &mut Vec<Event>) {
        let a = Self::take_finished_play(&mut self.a_to_b, reason);
        let b = Self::take_finished_play(&mut self.b_to_a, reason);
        if let Some(finished) = a {
            events.push(self.play_finished_event(finished));
        }
        if let Some(finished) = b {
            events.push(self.play_finished_event(finished));
        }
    }

    /// Take a direction's in-flight injection (stopping it), reporting it as a [`FinishedPlay`] for
    /// `reason` only when it was a `play_media` prompt (a DTMF burst carries no `play_id`, an empty
    /// direction nothing).
    fn take_finished_play(
        direction: &mut Direction,
        reason: PlayEndReason,
    ) -> Option<FinishedPlay> {
        match direction.injection.take() {
            Some(Injection::Audio {
                play_id, played_ms, ..
            }) => Some(FinishedPlay {
                play_id,
                reason,
                played_ms,
            }),
            _ => None,
        }
    }

    /// Build the [`Event::PlayFinished`] for a just-ended prompt, keyed by this call's identifiers
    /// (the same `call_id` / `from_tag` / `to_tag` triple as [`Event::Dtmf`]).
    fn play_finished_event(&self, finished: FinishedPlay) -> Event {
        Event::PlayFinished {
            call_id: self.call_id.clone(),
            from_tag: self.from_tag.clone(),
            to_tag: self.to_tag.clone(),
            play_id: finished.play_id,
            reason: finished.reason,
            played_ms: Some(finished.played_ms),
        }
    }

    /// The direction whose **ingress** decodes a leg's audio: leg A's RTP is decoded by `a_to_b`
    /// (its ingress faces A), leg B's by `b_to_a`. SIPREC forks a source leg's decoded audio, so it
    /// taps the direction that decodes that leg — not the one whose egress faces it (RFC 7866 §6).
    fn ingress_direction(&mut self, source_a: bool) -> &mut Direction {
        if source_a {
            &mut self.a_to_b
        } else {
            &mut self.b_to_a
        }
    }

    /// Attach a SIPREC / monitor fork sink to a source leg's decoded ingress audio
    /// ([`MediaControl::AddFork`]). `source_a` selects which leg is forked: `true` ⇒ leg A's audio,
    /// `false` ⇒ leg B's. The sink (an [`super::engine`]-built `RtpForkSink`) re-encodes each decoded
    /// frame toward the subscriber; the engine drains its output channel to the datapath.
    pub fn add_fork(&mut self, source_a: bool, sink: Box<dyn MediaSink>) {
        self.ingress_direction(source_a).forks.push(sink);
    }

    /// Detach every fork on a source leg's ingress ([`MediaControl::RemoveFork`]). Finalizes each sink
    /// (a no-op for `RtpForkSink`) and drops it, closing its output channel so the engine's drain task
    /// exits cleanly.
    pub fn remove_forks(&mut self, source_a: bool) {
        let direction = self.ingress_direction(source_a);
        for fork in &mut direction.forks {
            fork.finish();
        }
        direction.forks.clear();
    }

    /// Detach only the forks a source leg carries under `tag` ([`MediaControl::RemoveForkTagged`]),
    /// leaving every other sink on that leg attached. This is what lets a WS tee (tagged with its
    /// stream id) be detached mid-call without tearing down a SIPREC subscription forking the same leg
    /// — [`Self::remove_forks`] clears them all, which is right at teardown and wrong for a detach.
    pub fn remove_forks_tagged(&mut self, source_a: bool, tag: &str) {
        let direction = self.ingress_direction(source_a);
        for fork in &mut direction.forks {
            if fork.tag() == Some(tag) {
                fork.finish();
            }
        }
        direction.forks.retain(|fork| fork.tag() != Some(tag));
    }

    /// Number of forks attached to a source leg's ingress (test/observability helper).
    #[must_use]
    pub fn fork_count(&self, source_a: bool) -> usize {
        if source_a {
            self.a_to_b.forks.len()
        } else {
            self.b_to_a.forks.len()
        }
    }

    /// Attach a SIPREC / monitor **raw-RTP tee** to a source leg's ingress ([`MediaControl::AddRawTee`]).
    /// `source_a` selects the leg: `true` ⇒ leg A's ingress, `false` ⇒ leg B's. Each accepted ingress
    /// datagram is copied byte-for-byte toward the SRS (the leg's negotiated codec, RFC 7866 §6) — no
    /// decode/re-encode, so it works for any codec the engine cannot encode (e.g. AMR-WB).
    pub fn add_raw_tee(&mut self, source_a: bool, tee: RawTee) {
        self.ingress_direction(source_a).raw_tee.push(tee);
    }

    /// Remove the raw tee for a specific subscriber endpoint on a source leg's ingress
    /// ([`MediaControl::RemoveRawTee`]). Removing one subscriber leaves any others intact (MPTY: one
    /// subscription may tap several legs, and a leg may carry several subscriptions).
    pub fn remove_raw_tee(&mut self, source_a: bool, subscriber_endpoint: EndpointId) {
        self.ingress_direction(source_a)
            .raw_tee
            .retain(|tee| tee.subscriber_endpoint != subscriber_endpoint);
    }

    /// Number of raw-tee targets on a source leg's ingress (test/observability helper).
    #[must_use]
    pub fn raw_tee_count(&self, source_a: bool) -> usize {
        if source_a {
            self.a_to_b.raw_tee.len()
        } else {
            self.b_to_a.raw_tee.len()
        }
    }

    /// Advance one playout tick: emit any active injection's egress packet (a prompt that drains this
    /// tick appends its [`Event::PlayFinished`] `Completed` to `events`), else — on a comfort-idle
    /// single-leg leg — one continuous comfort-noise frame. Comfort is suppressed while the `echo` verb
    /// reflects (`echo_into` already emits the reflected stream on the packet path; a second egress
    /// stream on the same SSRC would collide), so the idle stream and the echo reflect never coexist.
    pub fn tick(&mut self, out: &mut Vec<Outbound>, events: &mut Vec<Event>) {
        let comfort_enabled = !self.echo;
        if let Some(finished) = self.a_to_b.tick_egress(comfort_enabled, out) {
            events.push(self.play_finished_event(finished));
        }
        if let Some(finished) = self.b_to_a.tick_egress(comfort_enabled, out) {
            events.push(self.play_finished_event(finished));
        }
    }

    /// Append this call's periodic per-leg [`Event::CallQuality`] reports (RFC 3550 §6.4.1 loss/jitter
    /// with an ITU-T G.107 MOS) — the 2-party transcode counterpart to the conference per-participant
    /// quality report. One event per direction that has received audio: the `a_to_b` ingress measures
    /// what party A (the offerer, `from_tag`) sent, the `b_to_a` ingress what party B (`to_tag`) sent.
    /// A direction with no inbound stream yet, or a leg whose tag is unknown, contributes nothing.
    /// Reads the accumulated estimates only — no per-packet or per-frame work, so it is safe on the
    /// ~5 s cadence the actor drives it at.
    pub fn build_quality_events(&self, out: &mut Vec<Event>) {
        if let Some(event) = self.a_to_b.quality_event(&self.call_id, &self.from_tag) {
            out.push(event);
        }
        if let Some(to_tag) = self.to_tag.as_deref() {
            if let Some(event) = self.b_to_a.quality_event(&self.call_id, to_tag) {
                out.push(event);
            }
        }
    }

    /// Fold both directions' current quality into their running `QualityAggregate`s for the call's
    /// end-of-call CDR. Driven on the same ~5 s cadence as [`Self::build_quality_events`]; `at_ms` is
    /// the call-relative age of the sample, carried through to the min/max timestamps in the summary.
    pub fn accumulate_quality(&mut self, at_ms: u64) {
        self.a_to_b.accumulate_quality(at_ms);
        self.b_to_a.accumulate_quality(at_ms);
    }

    /// This call's per-direction end-of-call quality (RFC 3550 reception stats + running G.107 MOS) for
    /// the CDR — `a_to_b` measures what the offerer (`from_tag`) sent, `b_to_a` what the answerer
    /// (`to_tag`) sent. Requested by the engine over the actor mailbox ([`MediaControl::Report`]) at
    /// teardown, before the task is aborted.
    pub fn final_quality(&self) -> FinalCallQuality {
        FinalCallQuality {
            a_to_b: self.a_to_b.quality_snapshot(),
            b_to_a: self.b_to_a.quality_snapshot(),
        }
    }

    /// Whether either direction has an active injection (the actor only needs the ticker while so).
    #[must_use]
    pub fn has_injection(&self) -> bool {
        self.a_to_b.injection.is_some() || self.b_to_a.injection.is_some()
    }

    /// Whether the actor must run the playout tick this cycle: an active injection, or a comfort-idle
    /// single-leg leg that is not currently reflecting (`echo` off) — the latter emits a continuous
    /// comfort-noise stream, so the tick fires every cycle for the life of the leg.
    #[must_use]
    pub fn needs_egress_tick(&self) -> bool {
        self.has_injection() || (!self.echo && self.a_to_b.comfort.is_some())
    }

    /// Mark this call as a **single-leg** local-answer / IVR call whose caller-facing egress idles on
    /// comfort noise instead of looping the caller's audio back (self-echo). Only `a_to_b` faces the
    /// caller — [`MediaCall::process`] runs the `a_to_b` branch for the shared endpoint and prompts
    /// inject there (`toward_a = false`) — so comfort idles on `a_to_b`. `cn_pt` is the negotiated CN
    /// egress payload type (`None` ⇒ audio-encoded low-level noise); see the `ComfortNoise` type.
    #[must_use]
    pub fn with_comfort_idle(mut self, cn_pt: Option<u8>) -> Self {
        self.a_to_b.enable_comfort_idle(cn_pt);
        self
    }

    /// Take the recorded WAV bytes for both directions (mixed into a 2-channel-ish concatenation is
    /// out of scope; we write each direction sequentially as mono), draining the recorders.
    fn take_recordings(&mut self) -> Vec<(String, Vec<u8>)> {
        let mut files = Vec::new();
        let Some(base) = self.record_path.clone() else {
            return files;
        };
        if let Some(recorder) = self.a_to_b.recorder.take() {
            if recorder.sample_count() > 0 {
                files.push((
                    format!("{base}/{}-a.wav", self.call_id),
                    recorder.into_wav(),
                ));
            }
        }
        if let Some(recorder) = self.b_to_a.recorder.take() {
            if recorder.sample_count() > 0 {
                files.push((
                    format!("{base}/{}-b.wav", self.call_id),
                    recorder.into_wav(),
                ));
            }
        }
        files
    }
}

/// A control message to a running [`MediaCall`] actor.
pub enum MediaControl {
    /// Replace egress audio with silence (`true`) or resume (`false`).
    Silence(bool),
    /// Drop egress audio (`true`) or resume (`false`).
    Block(bool),
    /// Echo each party's ingress audio back to itself (`true`) or resume normal forwarding (`false`).
    Echo(bool),
    /// Block (`blocked = true`) or resume (`false`) relaying one leg's RFC 4733 telephone-events
    /// (`block DTMF`). `source_a` selects the blocked source leg (`true` ⇒ leg A). Detection still
    /// fires while blocked, so the controller sees the digit — only the peer-bound relay is dropped.
    BlockDtmf { source_a: bool, blocked: bool },
    /// Play a prompt toward a party (`toward_a`): the player owns its source-rate PCM. `play_id` is
    /// the accept's playback id, carried on the [`Event::PlayFinished`] emitted when the prompt ends.
    PlayAudio {
        toward_a: bool,
        player: Box<PcmPlayer>,
        play_id: u64,
    },
    /// Play a DTMF sequence toward a party: `digits` is the (validated) multi-digit code, each digit
    /// played `duration_ms` long with `pause_ms` of inter-digit silence (RFC 4733 telephone-events).
    PlayDtmf {
        toward_a: bool,
        digits: String,
        duration_ms: u32,
        volume: u8,
        pause_ms: u32,
    },
    /// Stop any prompt / DTMF injection on both directions.
    StopPlay,
    /// Attach a SIPREC / monitor fork to a source leg's decoded ingress audio (`source_a` selects
    /// leg A vs leg B). The engine builds the `RtpForkSink` and owns the matching output channel +
    /// drain task (RFC 7866 SIPREC; the subscriber is send-only — engine → SRS — no inbound media).
    AddFork {
        source_a: bool,
        sink: Box<dyn MediaSink>,
    },
    /// Detach every fork on a source leg's ingress, closing their output channels.
    RemoveFork { source_a: bool },
    /// Detach only the forks a source leg carries under `tag`, leaving the others attached — how a WS
    /// tee detaches without disturbing a SIPREC subscription forking the same leg.
    RemoveForkTagged { source_a: bool, tag: String },
    /// Attach a SIPREC / monitor **raw-RTP tee** to a source leg's ingress (`source_a` selects leg A
    /// vs leg B). The leg's original ingress RTP is copied byte-for-byte toward the SRS — its
    /// negotiated codec, no re-encode (RFC 7866 §6). Send-only: the engine installs no inbound flow on
    /// the subscriber endpoint, so there is no RTPBleed surface.
    AddRawTee { source_a: bool, tee: RawTee },
    /// Remove the raw tee for a subscriber endpoint on a source leg's ingress.
    RemoveRawTee {
        source_a: bool,
        subscriber_endpoint: EndpointId,
    },
    /// Begin a raw-RTP pcap capture (`start recording`): every accepted ingress datagram on either
    /// leg is copied to `capture.sender`. The engine owns the drain task that frames + streams it to
    /// disk (so the actor never blocks on I/O).
    StartRecording { capture: PcapCapture },
    /// Stop the raw-RTP pcap capture (`stop recording`): drop the sink so the drain task finalizes.
    StopRecording,
    /// Snapshot the call's end-of-call quality (per-direction MOS / loss / jitter) and return it over
    /// `reply`, without stopping the actor. The engine sends this at teardown to build the call's CDR
    /// before the task is aborted; the reply is best-effort (dropped if the actor is already gone, in
    /// which case the engine logs a counters-only CDR).
    Report {
        reply: tokio::sync::oneshot::Sender<FinalCallQuality>,
    },
    /// Tear the call down: flush recordings and exit the actor loop.
    Stop,
}

/// A message into a [`MediaCall`] actor's single mailbox: a redirected datagram or a control op.
pub enum MediaInput {
    /// A datagram redirected by the datapath for one of this call's endpoints.
    Packet(RxPacket),
    /// A control operation from the engine.
    Control(MediaControl),
}

/// The registry of media-processing calls: routes redirected datagrams to the owning actor's mailbox
/// and holds each call's control handle for teardown. Mirrors the [`crate::srtp_bridge::SrtpBridge`]
/// "registry + dispatcher" shape so the single redirect dispatcher can route by [`EndpointId`].
#[derive(Default)]
pub struct MediaRegistry {
    /// Endpoint → the owning call actor's mailbox (the dispatcher's routing table).
    routes: DashMap<EndpointId, flume::Sender<MediaInput>>,
    /// Call-id → control handle (mailbox + endpoints), for control verbs and teardown.
    calls: DashMap<String, CallHandle>,
}

/// A handle to a running media-call actor.
struct CallHandle {
    mailbox: flume::Sender<MediaInput>,
    endpoints: [EndpointId; 2],
    /// Companion (non-muxed) RTCP endpoints routed to this actor, if any (secure-transcode leg).
    rtcp_endpoints: Vec<EndpointId>,
    task: tokio::task::JoinHandle<()>,
    /// `true` for a promoted passthrough relay (no transcode) — distinguishes it from a transcoding
    /// call so the engine's silence/play/DTMF guards stay correct.
    relay_only: bool,
    /// The call's shared SDES-SRTP leg for a secure-transcode (`SrtpMedia`) call — retained so an HA
    /// checkpoint can read its live SRTP rollover (RFC 3711 §3.3.1), which the running actor otherwise
    /// owns exclusively. `None` for a plaintext transcode / relay call.
    secure_leg: Option<Arc<Mutex<SecureLeg>>>,
}

impl MediaRegistry {
    /// Whether the registry routes datagrams for `endpoint` (the dispatcher's predicate).
    #[must_use]
    pub fn owns(&self, endpoint: EndpointId) -> bool {
        self.routes.contains_key(&endpoint)
    }

    /// Test-only: the two ingress endpoints a registered call routes. They are **equal** for an
    /// offer-only single-leg self-echo call (both directions face the caller on one endpoint) and
    /// **distinct** for a 2-leg call — the structural difference the echo tests assert on.
    #[cfg(test)]
    pub(crate) fn call_endpoints(&self, call_id: &str) -> Option<[EndpointId; 2]> {
        self.calls.get(call_id).map(|handle| handle.endpoints)
    }

    /// Route a redirected datagram to its owning call actor (drop on a full or closed mailbox —
    /// late media is worthless).
    pub fn dispatch(&self, packet: RxPacket) {
        if let Some(mailbox) = self.routes.get(&packet.endpoint) {
            if mailbox.try_send(MediaInput::Packet(packet)).is_err() {
                tracing::trace!("media-call mailbox full or closed; dropping redirected datagram");
            }
        }
    }

    /// Register a built [`MediaCall`] and spawn its actor over `datapath`, with `events` as the
    /// owner's async event sink (DTMF events are pushed there). Returns once the actor is spawned.
    pub fn register<D>(&self, call: MediaCall, datapath: D, events: Option<flume::Sender<Event>>)
    where
        D: Datapath + Clone + Send + 'static,
    {
        let call_id = call.call_id.clone();
        let endpoints = call.endpoints();
        let rtcp_endpoints = call.rtcp_endpoints();
        let relay_only = call.is_relay_only();
        // Clone out the shared secure leg (if any) before the actor takes ownership of the `MediaCall`,
        // so an HA checkpoint can reach its SRTP rollover (RFC 3711 §3.3.1). The `Arc` is the same
        // instance the actor holds — reads are a brief, uncontended lock.
        let secure_leg = call.far_secure_leg();
        let (mailbox, inbox) = flume::bounded(1024);
        for endpoint in endpoints
            .iter()
            .copied()
            .chain(rtcp_endpoints.iter().copied())
        {
            self.routes.insert(endpoint, mailbox.clone());
        }
        let task = tokio::spawn(run_media_call(call, inbox, datapath, events));
        self.calls.insert(
            call_id,
            CallHandle {
                mailbox,
                endpoints,
                rtcp_endpoints,
                task,
                relay_only,
                secure_leg,
            },
        );
    }

    /// Send a control op to a call's actor, returning `false` if there is no such media call.
    pub fn control(&self, call_id: &str, control: MediaControl) -> bool {
        match self.calls.get(call_id) {
            Some(handle) => handle
                .mailbox
                .try_send(MediaInput::Control(control))
                .is_ok(),
            None => false,
        }
    }

    /// Whether `call_id` is registered in the media slow path at all (transcoding **or** a promoted
    /// relay-only call). A SIPREC raw tee can attach to either, so `subscribe_request` checks this.
    #[must_use]
    pub fn is_media_call(&self, call_id: &str) -> bool {
        self.calls.contains_key(call_id)
    }

    /// Snapshot the live SRTP rollover of a secure-transcode (`SrtpMedia`) call's shared [`SecureLeg`]
    /// for an HA checkpoint — the per-SSRC ROC + outbound SRTCP index that are estimated from observed
    /// packets and so cannot be re-derived from the SDES keys on a standby (RFC 3711 §3.3.1 / §3.4).
    /// `None` if the call is unknown or is not a secure-transcode call. The lock is held only for the
    /// snapshot copy (no `.await` under it), so it never blocks the actor's per-packet path materially.
    #[must_use]
    pub fn rollover_snapshot(&self, call_id: &str) -> Option<SecureLegRollover> {
        let handle = self.calls.get(call_id)?;
        let leg = handle.secure_leg.as_ref()?;
        let guard = leg.lock().ok()?;
        Some(guard.rollover_snapshot())
    }

    /// Whether `call_id` is a **transcoding** media call (decode/re-encode), i.e. registered and not
    /// relay-only. The silence/play/DTMF verbs need a transcoding call (they own the egress codec); a
    /// promoted passthrough relay forwards opaque payloads and cannot synthesize audio.
    #[must_use]
    pub fn is_transcoding_call(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|handle| !handle.relay_only)
    }

    /// Count of live **transcoding** media calls (excludes promoted relay-only passthrough calls) —
    /// the expensive, decode/re-encode subset the cluster `load` command reports so a dispatcher can
    /// weight a node's real cost above its raw call count.
    #[must_use]
    pub fn transcode_call_count(&self) -> usize {
        self.calls
            .iter()
            .filter(|entry| !entry.value().relay_only)
            .count()
    }

    /// Whether `call_id` is a promoted relay-only call (a passthrough leg taken to userspace for a
    /// SIPREC raw tee). Used to decide whether `unsubscribe` should demote it back to in-kernel
    /// `Forward` once its last subscription is gone.
    #[must_use]
    pub fn is_relay_call(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|handle| handle.relay_only)
    }

    /// Snapshot a live media call's end-of-call quality for the CDR (per-direction MOS / loss / jitter),
    /// by asking its actor over the mailbox. `None` if the call is unknown (e.g. a plain in-kernel relay
    /// with no actor), its mailbox is closed, or the actor does not answer within `timeout` — a slow or
    /// already-aborted actor must never stall teardown, so the engine then logs a counters-only CDR.
    pub async fn final_quality(
        &self,
        call_id: &str,
        timeout: std::time::Duration,
    ) -> Option<FinalCallQuality> {
        let mailbox = self.calls.get(call_id)?.mailbox.clone();
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if mailbox
            .try_send(MediaInput::Control(MediaControl::Report {
                reply: reply_tx,
            }))
            .is_err()
        {
            return None;
        }
        tokio::time::timeout(timeout, reply_rx).await.ok()?.ok()
    }

    /// Tear a call's actor down: stop it (flushing recordings), drop its routes, and abort the task.
    pub fn deregister(&self, call_id: &str) {
        if let Some((_, handle)) = self.calls.remove(call_id) {
            let _ = handle
                .mailbox
                .try_send(MediaInput::Control(MediaControl::Stop));
            for endpoint in handle
                .endpoints
                .iter()
                .copied()
                .chain(handle.rtcp_endpoints.iter().copied())
            {
                self.routes.remove(&endpoint);
            }
            handle.task.abort();
        }
    }
}

/// The async actor for one media-processing call: drain its mailbox, run [`MediaCall::process`], and
/// perform the datapath I/O + event emission. Exits on `Stop`, mailbox close, or task abort.
async fn run_media_call<D>(
    mut call: MediaCall,
    inbox: flume::Receiver<MediaInput>,
    datapath: D,
    events: Option<flume::Sender<Event>>,
) where
    D: Datapath,
{
    let mut outbound = Vec::new();
    let mut emitted = Vec::new();
    // The playout clock drives injected prompts / DTMF (PlayMedia / PlayDtmf). It runs always but is
    // a no-op unless an injection is active; `Skip` keeps it from bursting after a stall.
    let mut ticker = tokio::time::interval(INJECT_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Periodic per-leg call-quality reporting rides the same ticker (every `QUALITY_INTERVAL_TICKS`),
    // so a 2-party transcode call surfaces RFC 3550 loss/jitter + G.107 MOS on the control channel the
    // way a conference participant does — without any per-packet work.
    let mut ticks_since_quality = 0u64;
    // Call-relative age, advanced one `INJECT_TICK` per playout tick, stamped onto each end-of-call
    // MOS min/max so the CDR can render "worst at M:SS" (rtpengine parity). Approximate under a stalled
    // reactor (the ticker's `Skip` may drop ticks) — a CDR label, never a control/DSP clock.
    let mut elapsed_ms = 0u64;
    loop {
        tokio::select! {
            input = inbox.recv_async() => {
                let Ok(input) = input else { break };
                match input {
                    MediaInput::Packet(packet) => {
                        outbound.clear();
                        emitted.clear();
                        // Stamp media activity for the timeout sweep only when the packet passes the
                        // source gate (a spoofed spray must not keep an idle path alive). A redirected
                        // media leg's ingress otherwise never touches the datapath's `last_seen` (the
                        // Redirect arm doesn't, unlike the in-kernel Forward relay), so without this an
                        // actively-transcoding/echoing call would be reaped mid-call — same fix the
                        // conference actor already applies.
                        if call.process(&packet, &mut outbound, &mut emitted) {
                            datapath.note_activity(packet.endpoint);
                        }
                        send_all(&datapath, &mut outbound).await;
                        emit_events(&mut emitted, &events);
                    }
                    MediaInput::Control(MediaControl::Silence(on)) => call.set_silenced(on),
                    MediaInput::Control(MediaControl::Block(on)) => call.set_blocked(on),
                    MediaInput::Control(MediaControl::Echo(on)) => call.set_echo(on),
                    MediaInput::Control(MediaControl::BlockDtmf { source_a, blocked }) => {
                        call.set_dtmf_blocked(source_a, blocked);
                    }
                    MediaInput::Control(MediaControl::PlayAudio { toward_a, player, play_id }) => {
                        // Starting a prompt supersedes any prior one on the direction, which emits a
                        // `PlayFinished{Superseded}` for the old play_id.
                        emitted.clear();
                        call.start_play_audio(toward_a, *player, play_id, &mut emitted);
                        emit_events(&mut emitted, &events);
                    }
                    MediaInput::Control(MediaControl::PlayDtmf { toward_a, digits, duration_ms, volume, pause_ms }) => {
                        call.start_play_dtmf(toward_a, &digits, duration_ms, volume, pause_ms);
                    }
                    MediaInput::Control(MediaControl::StopPlay) => {
                        // An explicit stop ends any prompt with `PlayFinished{Stopped}`.
                        emitted.clear();
                        call.stop_play(&mut emitted);
                        emit_events(&mut emitted, &events);
                    }
                    MediaInput::Control(MediaControl::AddFork { source_a, sink }) => {
                        call.add_fork(source_a, sink);
                    }
                    MediaInput::Control(MediaControl::RemoveFork { source_a }) => {
                        call.remove_forks(source_a);
                    }
                    MediaInput::Control(MediaControl::RemoveForkTagged { source_a, tag }) => {
                        call.remove_forks_tagged(source_a, &tag);
                    }
                    MediaInput::Control(MediaControl::AddRawTee { source_a, tee }) => {
                        call.add_raw_tee(source_a, tee);
                    }
                    MediaInput::Control(MediaControl::RemoveRawTee { source_a, subscriber_endpoint }) => {
                        call.remove_raw_tee(source_a, subscriber_endpoint);
                    }
                    MediaInput::Control(MediaControl::StartRecording { capture }) => {
                        call.start_recording(capture);
                    }
                    MediaInput::Control(MediaControl::StopRecording) => call.stop_recording(),
                    MediaInput::Control(MediaControl::Report { reply }) => {
                        // Read-only snapshot for the engine's CDR; the actor keeps running.
                        let _ = reply.send(call.final_quality());
                    }
                    MediaInput::Control(MediaControl::Stop) => break,
                }
            }
            _ = ticker.tick() => {
                elapsed_ms = elapsed_ms.saturating_add(INJECT_TICK.as_millis() as u64);
                if call.needs_egress_tick() {
                    outbound.clear();
                    emitted.clear();
                    // A prompt that drains this tick appends its `PlayFinished{Completed}`; a
                    // comfort-idle single-leg leg emits its continuous comfort-noise frame.
                    call.tick(&mut outbound, &mut emitted);
                    send_all(&datapath, &mut outbound).await;
                    emit_events(&mut emitted, &events);
                }
                // Periodic per-leg quality estimate (jitter/loss/MOS) on the control channel, so SIPhon
                // sees live 2-party (relay/transcode) call quality without parsing RTCP itself — the
                // control-channel complement to the HEP QoS export. The same sample is folded into the
                // per-direction running aggregate for the end-of-call CDR.
                ticks_since_quality += 1;
                if ticks_since_quality >= QUALITY_INTERVAL_TICKS {
                    ticks_since_quality = 0;
                    call.accumulate_quality(elapsed_ms);
                    emitted.clear();
                    call.build_quality_events(&mut emitted);
                    emit_events(&mut emitted, &events);
                }
            }
        }
    }
    // Any prompt still in flight when the actor exits ended with the leg — report it as
    // `PlayFinished{Error}` (best-effort) so a controller awaiting it is released. siphon-sip carries
    // its own fallback timeout, since a hard task-abort may pre-empt this teardown.
    emitted.clear();
    call.finish_pending_plays(&mut emitted);
    emit_events(&mut emitted, &events);
    // Flush recordings on teardown (one-shot; tokio::fs keeps the runtime non-blocking).
    for (path, bytes) in call.take_recordings() {
        if let Err(error) = tokio::fs::write(&path, &bytes).await {
            tracing::warn!(%error, path, "media-pipeline failed to write recording");
        } else {
            tracing::info!(path, "media-pipeline wrote recording");
        }
    }
}

/// RFC 5761 demux: a datagram whose second byte's payload-type field is in `64..=95` is RTCP (never a
/// valid RTP payload type at that offset), so the muxed RTP/RTCP flow can tell them apart.
fn is_rtcp_datagram(data: &[u8]) -> bool {
    data.len() >= 2 && (64..=95).contains(&(data[1] & 0x7f))
}

/// Push every queued control event to the owner's per-client sink, draining the buffer. A full or
/// closed sink drops the event (best-effort, never blocks the actor) — the same posture the per-packet
/// path takes for `Event::Dtmf`.
fn emit_events(emitted: &mut Vec<Event>, sink: &Option<flume::Sender<Event>>) {
    for event in emitted.drain(..) {
        if let Some(sink) = sink {
            if sink.try_send(event).is_err() {
                tracing::debug!("media-pipeline event dropped (sink full or closed)");
            }
        }
    }
}

/// Transmit every queued outbound datagram, draining the buffer. Send errors are logged, never
/// propagated — a transient socket error must not stall the actor.
async fn send_all<D: Datapath>(datapath: &D, outbound: &mut Vec<Outbound>) {
    for datagram in outbound.drain(..) {
        if let Err(error) = datapath
            .send(datagram.endpoint, datagram.dst, &datagram.data)
            .await
        {
            tracing::debug!(%error, "media-pipeline send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_codec::g711::G711;
    use siphon_rtp_codec::g722::G722;
    use siphon_rtp_codec::l16::L16;
    use std::net::{IpAddr, Ipv4Addr};

    const A_ADDR: &str = "127.0.0.2:5000";
    const B_ADDR: &str = "127.0.0.3:6000";

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("addr")
    }

    fn endpoint(id: u64) -> EndpointId {
        EndpointId(id)
    }

    /// Build a µ-law(A) ↔ A-law(B) transcoding call, both legs 8 kHz/20 ms.
    fn ulaw_alaw_call() -> MediaCall {
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1), // A's engine socket
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2), // B's engine socket
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::alaw()),
            egress_ssrc: 0xB000_0001,
            egress_payload_type: 8,
            telephone_event_in: Some(101),
            telephone_event_out: Some(101),
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G711::alaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 0xA000_0001,
            egress_payload_type: 0,
            telephone_event_in: Some(101),
            telephone_event_out: Some(101),
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        MediaCall::new(
            "call-1",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        )
    }

    fn ulaw_rtp(sequence: u16, payload_byte: u8) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 0x1234_5678,
        };
        let payload = [payload_byte; 160];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    fn rx(endpoint_id: u64, source: &str, data: Vec<u8>) -> RxPacket {
        RxPacket {
            endpoint: endpoint(endpoint_id),
            source: addr(source),
            arrival: 0,
            data: Bytes::from(data),
        }
    }

    /// A µ-law RTP packet with a caller-chosen SSRC (RFC 3550 §5.1) — drives the SSRC-consistent
    /// symmetric-latch tests, which must distinguish a NAT rebind from a hijack by SSRC.
    fn ulaw_rtp_with_ssrc(sequence: u16, ssrc: u32) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc,
        };
        let payload = [0x40u8; 160];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn symmetric_latch_moves_reply_only_on_matching_ssrc() {
        // The reverse (B→A) reply follows a genuine NAT rebind — a new source carrying the same RTP
        // SSRC — but a spray from a new source with a *different* SSRC cannot steal it
        // (docs/security-and-nat.md §4 layer 3; RFC 3550 §8). The userspace-transcode analogue of the
        // datapath `symmetric_latch_follows_ssrc_rebind_but_rejects_hijack` test.
        let mut call = ulaw_alaw_call();
        // A symmetric-NAT A leg accepts any source, so the SSRC — not the source IP — decides.
        call.a_to_b.accepted_source = SourceFilter::Any;
        let mut out = Vec::new();
        let mut events = Vec::new();

        const STREAM: u32 = 0x0A0A_0A0A;
        // A's stream from its first source latches the B→A reply to it.
        call.process(
            &rx(1, "127.0.0.2:5000", ulaw_rtp_with_ssrc(1, STREAM)),
            &mut out,
            &mut events,
        );
        assert_eq!(
            call.b_to_a.egress_dst,
            addr("127.0.0.2:5000"),
            "the first accepted source latches the reply"
        );

        // A spray from a NEW source carrying a DIFFERENT SSRC is a hijack — the reply must not move.
        call.process(
            &rx(1, "127.0.0.9:5000", ulaw_rtp_with_ssrc(2, 0x9999_9999)),
            &mut out,
            &mut events,
        );
        assert_eq!(
            call.b_to_a.egress_dst,
            addr("127.0.0.2:5000"),
            "a wrong-SSRC source cannot steal the reply direction"
        );

        // The SAME SSRC from a new source is a genuine NAT rebind — the reply follows it.
        call.process(
            &rx(1, "127.0.0.5:5000", ulaw_rtp_with_ssrc(3, STREAM)),
            &mut out,
            &mut events,
        );
        assert_eq!(
            call.b_to_a.egress_dst,
            addr("127.0.0.5:5000"),
            "a same-SSRC rebind re-latches the reply"
        );
    }

    #[test]
    fn forged_srtp_packet_does_not_move_the_reply_direction() {
        use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
        // B2: on a secure-transcode leg the reverse egress must be re-pointed only *after* SRTP auth.
        // A forged, auth-failing packet from the gated IP must not steal the reply direction toward B.
        let engine_key = SrtpKeyMaterial::from_inline_bytes(&[7u8; 30]).expect("engine key");
        let b_key = SrtpKeyMaterial::from_inline_bytes(&[9u8; 30]).expect("b key");
        let actor_leg = Arc::new(Mutex::new(SecureLeg::new(&engine_key, &b_key)));
        let mut peer_leg = SecureLeg::new(&b_key, &engine_key); // the secure peer B

        // µ-law↔µ-law transcode; B (endpoint 2) is the secure peer, so `b_to_a` decrypts ingress and
        // `a_to_b` encrypts egress toward B (exactly what `with_far_secure_leg` wires).
        let direction =
            |ingress: u64, src: &str, egress: u64, dst: &str, ssrc: u32| DirectionConfig {
                ingress_endpoint: endpoint(ingress),
                accepted_source: SourceFilter::Exact(addr(src).ip()),
                egress_endpoint: endpoint(egress),
                egress_dst: addr(dst),
                decoder: Box::new(G711::ulaw()),
                encoder: Box::new(G711::ulaw()),
                egress_ssrc: ssrc,
                egress_payload_type: 0,
                telephone_event_in: None,
                telephone_event_out: None,
                recorder: None,
                noise_suppression: false,
                echo_cancellation: false,
                produce_echo_reference: false,
                ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
            };
        let mut call = MediaCall::new(
            "secure",
            "tag-a",
            Some("tag-b".into()),
            direction(1, A_ADDR, 2, B_ADDR, 0xB000_0001),
            direction(2, B_ADDR, 1, A_ADDR, 0xA000_0001),
            true,
            None,
        )
        .with_far_secure_leg(actor_leg.clone());
        let mut out = Vec::new();
        let mut events = Vec::new();

        // An authentic B packet (encrypted by the peer) from a fresh source port latches the A→B
        // reply toward it — proving the symmetric latch still works on a secure leg.
        let b_plain = ulaw_rtp_with_ssrc(1, 0xB0B0_B0B0);
        let mut b_srtp = Vec::new();
        peer_leg
            .protect(&b_plain, &mut b_srtp)
            .expect("peer encrypt");
        call.process(&rx(2, "127.0.0.3:7000", b_srtp), &mut out, &mut events);
        assert_eq!(
            call.a_to_b.egress_dst,
            addr("127.0.0.3:7000"),
            "an authentic B stream latches the reply toward B"
        );

        // A forged packet from the same gated IP (different port) that FAILS SRTP auth must not move
        // the reply — it is dropped before the latch (the B2 fix: latch after auth, not before).
        out.clear();
        let forged = ulaw_rtp_with_ssrc(2, 0xB0B0_B0B0); // never SRTP-protected → auth fails
        call.process(&rx(2, "127.0.0.3:9999", forged), &mut out, &mut events);
        assert_eq!(
            call.a_to_b.egress_dst,
            addr("127.0.0.3:7000"),
            "a forged, auth-failing packet must not steal the reply direction (B2)"
        );
        assert!(out.is_empty(), "a forged packet is dropped, not forwarded");
    }

    /// A G.722 RTP packet: PT 9, a 160-byte payload (20 ms of codes), timestamp on the 8 kHz RTP
    /// clock (RFC 3551 §4.5.2 — 160 timestamp units per 20 ms despite 16 kHz audio).
    fn g722_rtp(sequence: u16) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 9,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 0x1234_5678,
        };
        let payload = [0x55u8; 160];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn transcodes_ulaw_to_alaw_for_the_far_leg() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(100, 0xFF)), &mut out, &mut events);

        assert_eq!(out.len(), 1, "one transcoded packet toward B");
        let datagram = &out[0];
        assert_eq!(datagram.endpoint, endpoint(2), "sent from B's socket");
        let packet = RtpPacket::parse(&datagram.data).expect("parse");
        assert_eq!(packet.payload_type, 8, "re-encoded as A-law (PT 8)");
        assert_eq!(packet.ssrc, 0xB000_0001, "stamped with the A→B egress SSRC");
        assert_eq!(packet.payload.len(), 160);
        // µ-law 0xFF and A-law decode of that sample differ at the byte level → genuinely transcoded.
        assert_ne!(packet.payload, &[0xFFu8; 160][..]);
        assert!(events.is_empty());
    }

    #[test]
    fn quality_aggregate_tracks_min_avg_max_with_timestamps() {
        let mut aggregate = QualityAggregate::default();
        assert_eq!(aggregate.samples(), 0);
        assert!(aggregate.mos_average().is_none(), "no samples ⇒ no mean");
        assert!(aggregate.mos_min().is_none());

        // Three samples: a good open, a dip at 10 s, a peak at 15 s.
        aggregate.record(4.2, 5.0, 0.0, 5_000);
        aggregate.record(3.0, 12.0, 8.0, 10_000);
        aggregate.record(4.4, 2.0, 1.0, 15_000);

        assert_eq!(aggregate.samples(), 3);
        let mean = aggregate.mos_average().expect("mean");
        assert!(
            (mean - (4.2 + 3.0 + 4.4) / 3.0).abs() < 1e-4,
            "arithmetic mean MOS, got {mean}"
        );
        assert!((aggregate.mos_min().expect("min") - 3.0).abs() < 1e-6);
        assert_eq!(
            aggregate.mos_min_at_ms(),
            10_000,
            "the worst MOS is timestamped at its sample time"
        );
        assert!((aggregate.mos_max().expect("max") - 4.4).abs() < 1e-6);
        assert_eq!(aggregate.mos_max_at_ms(), 15_000);
        assert!(
            (aggregate.jitter_ms_max() - 12.0).abs() < 1e-6,
            "peak jitter across the call"
        );
        assert!(
            (aggregate.loss_percent_max() - 8.0).abs() < 1e-6,
            "peak loss across the call"
        );
    }

    #[test]
    fn accumulate_quality_folds_live_estimates_into_the_call_aggregate() {
        // Drive a real 2-party transcode call with a lossy, jittered ingress stream, fold two periodic
        // quality samples, and confirm the running aggregate captured a degraded mean MOS on the
        // inbound direction while the silent reverse direction folded nothing.
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        for (sequence, arrival) in [(0u16, 0u64), (1, 20_000), (3, 75_000), (4, 85_000)] {
            call.process(
                &rx_at(1, A_ADDR, arrival, ulaw_rtp(sequence, 0x40)),
                &mut out,
                &mut events,
            );
        }

        call.accumulate_quality(5_000);
        call.accumulate_quality(10_000);

        // The end-of-call snapshot the engine reads for the CDR.
        let quality = call.final_quality();
        assert_eq!(
            quality.a_to_b.mos_samples, 2,
            "two samples folded on the direction that received audio"
        );
        assert!(
            quality.a_to_b.packets_received > 0,
            "the inbound packets were counted"
        );
        let mean = quality.a_to_b.mos_average.expect("mean");
        assert!(
            mean > 1.0 && mean < 3.5,
            "20% loss ⇒ a degraded mean MOS in (1, 3.5), got {mean}"
        );
        assert!(quality.a_to_b.loss_percent > 0.0, "loss captured");
        assert!(
            quality.a_to_b.loss_percent_max > 0.0,
            "peak loss captured across samples"
        );
        assert_eq!(
            quality.b_to_a.mos_samples, 0,
            "B→A never received a packet ⇒ nothing folded"
        );
    }

    #[test]
    fn passive_rtt_from_relayed_rtcp_feeds_the_leg_mos_delay() {
        // RFC 3550 §6.4.1: the engine reconstructs the engine↔party round-trip time from the plaintext
        // RTCP it relays — a Sender Report forwarded to a party, echoed as LSR/DLSR in that party's next
        // reception report. Deterministic on the logical clock (never `Instant::now()`).
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();

        // 1) B's Sender Report (NTP middle-32 = 0x1234_5678) is relayed toward A at t = 1.0 s.
        const NTP_B: u64 = 0xABCD_1234_5678_9ABC;
        let mut sr_b = [0u8; 64];
        let len = siphon_rtp_media::rtcp::write_sender_report(
            0xBBBB_BBBB,
            NTP_B,
            0,
            0,
            0,
            &[],
            &mut sr_b,
        )
        .expect("write B SR");
        call.process(
            &rx_at(2, B_ADDR, 1_000_000, sr_b[..len].to_vec()),
            &mut out,
            &mut events,
        );

        // 2) A's reception report (carried in an SR) echoes that SR — LSR = 0x1234_5678, DLSR = 0.5 s —
        //    on the stream A receives (the engine's A-facing egress SSRC), arriving at t = 1.6 s.
        let a_report = siphon_rtp_media::rtcp::ReceptionReport {
            ssrc: 0xA000_0001, // b_to_a.egress_ssrc — the stream A receives from the engine
            fraction_lost: 0,
            cumulative_lost: 0,
            extended_highest_seq: 0,
            jitter: 0,
            last_sr: 0x1234_5678,  // middle 32 bits of NTP_B
            delay_last_sr: 32_768, // 0.5 s in 1/65536 s units
        };
        let mut sr_a = [0u8; 64];
        let len = siphon_rtp_media::rtcp::write_sender_report(
            0xAAAA_AAAA,
            0,
            0,
            0,
            0,
            std::slice::from_ref(&a_report),
            &mut sr_a,
        )
        .expect("write A SR+RR");
        call.process(
            &rx_at(1, A_ADDR, 1_600_000, sr_a[..len].to_vec()),
            &mut out,
            &mut events,
        );

        // RTT = arrival(1.6 s) − DLSR(0.5 s) − relay_time(1.0 s) = 100 ms on A's leg (RFC 3550 §6.4.1).
        let quality = call.final_quality();
        assert_eq!(
            quality.a_to_b.rtt_ms,
            Some(100.0),
            "engine↔A RTT reconstructed from the relayed SR/RR exchange"
        );
        assert_eq!(
            quality.b_to_a.rtt_ms, None,
            "B never reported back ⇒ no RTT on the B leg (CDR marks it loss+jitter-only)"
        );
    }

    #[test]
    fn transcode_call_reports_call_quality_with_loss_and_jitter() {
        // A 2-party transcode call reports RFC 3550 loss/jitter + G.107 MOS on the control channel,
        // keyed by `call_id` (not `conference_id`) — the transcode counterpart to a conference
        // participant's quality report.
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // A→B ingress (endpoint 1): sequence 0,1,3,4 — packet 2 is lost (expected 5, received 4 ⇒
        // 20%). Arrivals drift off the 20 ms RTP pacing so a positive interarrival jitter accrues.
        for (sequence, arrival) in [(0u16, 0u64), (1, 20_000), (3, 75_000), (4, 85_000)] {
            call.process(
                &rx_at(1, A_ADDR, arrival, ulaw_rtp(sequence, 0x40)),
                &mut out,
                &mut events,
            );
        }
        // No DTMF/control events on the packet path; quality is a separate periodic emit.
        assert!(events.is_empty(), "no per-packet events for ordinary audio");

        let mut quality = Vec::new();
        call.build_quality_events(&mut quality);
        assert_eq!(
            quality.len(),
            1,
            "only A→B has an inbound stream ⇒ one quality event"
        );
        match &quality[0] {
            Event::CallQuality {
                conference_id,
                call_id,
                from_tag,
                jitter_ms,
                loss_percent,
                mos,
            } => {
                assert!(
                    conference_id.is_none(),
                    "a 2-party call carries no conference_id"
                );
                assert_eq!(call_id.as_deref(), Some("call-1"), "keyed by call_id");
                assert_eq!(from_tag, "tag-a", "measured on A's ingress (a_to_b)");
                // expected = 5 (seq 0..=4), received = 4 ⇒ 1 lost ⇒ 20%.
                assert!(
                    (*loss_percent - 20.0).abs() < 1e-9,
                    "1 of 5 packets lost ⇒ 20%, got {loss_percent}"
                );
                assert!(
                    *jitter_ms > 0.0,
                    "drifting arrivals ⇒ jitter, got {jitter_ms}"
                );
                // 20% loss on G.711 collapses the MOS well below a clean call (~2.6 on the E-model).
                assert!(
                    *mos > 1.0 && *mos < 3.5,
                    "20% loss ⇒ degraded MOS in (1, 3.5), got {mos}"
                );
            }
            other => panic!("expected CallQuality, got {other:?}"),
        }
    }

    #[test]
    fn transcode_call_quality_names_each_leg_by_its_tag() {
        // Clean audio on both legs ⇒ one quality event per direction, each keyed by `call_id` and
        // named by the sending leg's tag (A = `from_tag`, B = `to_tag`), both with a high MOS.
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        for sequence in 0..4u16 {
            let arrival = u64::from(sequence) * 20_000;
            call.process(
                &rx_at(1, A_ADDR, arrival, ulaw_rtp(sequence, 0x40)),
                &mut out,
                &mut events,
            );
            call.process(
                &rx_at(2, B_ADDR, arrival, ulaw_rtp(sequence, 0x40)),
                &mut out,
                &mut events,
            );
        }
        let mut quality = Vec::new();
        call.build_quality_events(&mut quality);
        assert_eq!(quality.len(), 2, "one quality event per direction");
        let mut tags: Vec<&str> = Vec::new();
        for event in &quality {
            let Event::CallQuality {
                conference_id,
                call_id,
                from_tag,
                loss_percent,
                mos,
                ..
            } = event
            else {
                panic!("expected CallQuality, got {event:?}");
            };
            assert!(conference_id.is_none());
            assert_eq!(call_id.as_deref(), Some("call-1"));
            assert_eq!(*loss_percent, 0.0, "in-order ⇒ no loss");
            assert!(*mos > 4.0, "clean call ⇒ good MOS, got {mos}");
            tags.push(from_tag);
        }
        tags.sort_unstable();
        assert_eq!(tags, ["tag-a", "tag-b"], "each leg named by its own tag");
    }

    /// Build a µ-law(A) → A-law(B) transcoding call whose **A→B egress** encoder packetizes at
    /// `egress_ptime_ms`, so the repacketizer must re-frame A's 20 ms ingress to that egress ptime.
    fn ulaw_to_alaw_egress_ptime(egress_ptime_ms: u8) -> MediaCall {
        use siphon_rtp_codec::g711::Variant;
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::new(Variant::Alaw, egress_ptime_ms)),
            egress_ssrc: 0xB000_0001,
            egress_payload_type: 8,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G711::alaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 0xA000_0001,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        MediaCall::new(
            "call-ptime",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        )
    }

    /// A µ-law RTP packet of `samples` bytes (one sample/byte at 8 kHz) with an explicit marker bit.
    fn ulaw_rtp_frame(sequence: u16, payload_byte: u8, samples: usize, marker: bool) -> Vec<u8> {
        let header = RtpHeader {
            marker,
            payload_type: 0,
            sequence,
            timestamp: u32::from(sequence) * samples as u32,
            ssrc: 0x1234_5678,
        };
        let payload = vec![payload_byte; samples];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn repacketizes_two_20ms_ingress_frames_into_one_40ms_egress_packet() {
        // A→B egress ptime overridden to 40 ms: two 20 ms µ-law frames in → one 40 ms A-law packet out.
        let mut call = ulaw_to_alaw_egress_ptime(40);
        let mut out = Vec::new();
        let mut events = Vec::new();

        // First 20 ms frame buffers — it is not yet a full 40 ms egress frame.
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        assert!(
            out.is_empty(),
            "first 20 ms frame buffered, no egress packet yet"
        );

        // Second 20 ms frame completes a 40 ms egress frame → exactly one packet.
        call.process(&rx(1, A_ADDR, ulaw_rtp(2, 0xFF)), &mut out, &mut events);
        assert_eq!(
            out.len(),
            1,
            "two 20 ms ingress frames → one 40 ms egress packet"
        );
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(packet.payload_type, 8, "re-encoded as A-law");
        assert_eq!(
            packet.payload.len(),
            320,
            "40 ms at 8 kHz = 320 samples (summed frame count)"
        );
        assert_eq!(packet.sequence, 0, "first egress sequence");
        assert_eq!(packet.timestamp, 0, "first egress timestamp");

        // Two more frames make the next 40 ms packet: sequence +1, timestamp +320 (RFC 3550 §5.1).
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(3, 0xFF)), &mut out, &mut events);
        assert!(out.is_empty());
        call.process(&rx(1, A_ADDR, ulaw_rtp(4, 0xFF)), &mut out, &mut events);
        assert_eq!(out.len(), 1);
        let next = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(
            next.sequence, 1,
            "sequence increments by 1 per egress packet"
        );
        assert_eq!(
            next.timestamp, 320,
            "timestamp advances by the 40 ms egress sample count (RFC 3550 §5.1)"
        );
    }

    #[test]
    fn repacketizes_one_20ms_ingress_frame_into_two_10ms_egress_packets() {
        // A→B egress ptime overridden to 10 ms: one 20 ms µ-law frame in → two 10 ms A-law packets out.
        let mut call = ulaw_to_alaw_egress_ptime(10);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        assert_eq!(
            out.len(),
            2,
            "one 20 ms ingress frame → two 10 ms egress packets"
        );
        let first = RtpPacket::parse(&out[0].data).expect("parse");
        let second = RtpPacket::parse(&out[1].data).expect("parse");
        assert_eq!(first.payload.len(), 80, "10 ms at 8 kHz");
        assert_eq!(second.payload.len(), 80);
        assert_eq!(
            second.sequence,
            first.sequence.wrapping_add(1),
            "two sequence numbers, +1"
        );
        assert_eq!(
            second.timestamp.wrapping_sub(first.timestamp),
            80,
            "10 ms apart in the 8 kHz egress clock"
        );
    }

    #[test]
    fn fractional_30ms_ingress_to_20ms_egress_loses_no_samples_across_the_stream() {
        // A→B egress ptime 20 ms (default), ingress 30 ms (240-sample µ-law): a fractional 3:2 ratio
        // that buffers across packets. Over the stream the egress packet count and contiguous RTP
        // timestamps prove no samples are lost or duplicated (byte-accounted).
        let mut call = ulaw_to_alaw_egress_ptime(20);
        let mut out = Vec::new();
        let mut events = Vec::new();
        let ingress_frames = 8u16;
        for sequence in 1..=ingress_frames {
            call.process(
                &rx(1, A_ADDR, ulaw_rtp_frame(sequence, 0x40, 240, false)),
                &mut out,
                &mut events,
            );
        }
        // 8 × 240 = 1920 egress samples ÷ 160 (20 ms) = exactly 12 egress packets, 0 leftover.
        assert_eq!(
            out.len(),
            12,
            "1920 egress samples re-framed into twelve 20 ms packets"
        );
        for (index, datagram) in out.iter().enumerate() {
            let packet = RtpPacket::parse(&datagram.data).expect("parse");
            assert_eq!(
                packet.payload.len(),
                160,
                "each egress packet is a full 20 ms frame"
            );
            assert_eq!(packet.sequence, index as u16, "contiguous egress sequence");
            assert_eq!(
                packet.timestamp,
                index as u32 * 160,
                "contiguous egress timestamps — no samples dropped or duplicated"
            );
        }
    }

    /// Build a G.722 ↔ G.722 call whose A→B egress packetizes at `egress_ptime_ms`. G.722 samples
    /// 16 kHz but clocks RTP at 8 kHz (RFC 3551 §4.5.2), so the egress timestamp steps by ptime × 8 kHz.
    fn g722_call(egress_ptime_ms: u8) -> MediaCall {
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G722::new(20)),
            encoder: Box::new(G722::new(egress_ptime_ms)),
            egress_ssrc: 0xB000_0009,
            egress_payload_type: 9,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G722::new(20)),
            encoder: Box::new(G722::new(20)),
            egress_ssrc: 0xA000_0009,
            egress_payload_type: 9,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        MediaCall::new(
            "call-g722",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        )
    }

    #[test]
    fn g722_egress_timestamp_uses_the_8khz_rtp_clock_not_the_16khz_sample_rate() {
        // A→B egress ptime overridden to 40 ms: four 20 ms G.722 frames → two 40 ms egress packets.
        let mut call = g722_call(40);
        let mut out = Vec::new();
        for sequence in 1..=4 {
            call.process(
                &rx(1, A_ADDR, g722_rtp(sequence)),
                &mut out,
                &mut Vec::new(),
            );
        }
        assert_eq!(
            out.len(),
            2,
            "four 20 ms G.722 frames → two 40 ms egress packets"
        );
        let first = RtpPacket::parse(&out[0].data).expect("parse");
        let second = RtpPacket::parse(&out[1].data).expect("parse");
        // 40 ms × 8000 Hz ÷ 1000 = 320 ts units — NOT 40 × 16000 ÷ 1000 = 640 (RFC 3551 §4.5.2).
        assert_eq!(
            second.timestamp.wrapping_sub(first.timestamp),
            320,
            "G.722 advances the 8 kHz RTP clock (ptime × 8000 ÷ 1000), not the 16 kHz sample rate"
        );
        assert_eq!(
            first.payload.len(),
            320,
            "40 ms of G.722 codes (2 samples/byte at 16 kHz)"
        );
    }

    #[test]
    fn egress_marker_follows_the_ingress_talkspurt_not_a_blind_copy() {
        // 1:1 20 ms transcode: the egress marker must track the sender's talkspurt boundary
        // (RFC 3550 §5.1), never a blind per-packet copy.
        let mut call = ulaw_to_alaw_egress_ptime(20);
        let mut out = Vec::new();
        let mut events = Vec::new();

        // Mid-stream (no marker) → egress marker clear.
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(1, 0xFF, 160, false)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1);
        assert!(
            !RtpPacket::parse(&out[0].data).expect("parse").marker,
            "no talkspurt marker to copy"
        );

        // Talkspurt restart (marker set) → the next egress packet carries the marker.
        out.clear();
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(2, 0xFF, 160, true)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1);
        assert!(
            RtpPacket::parse(&out[0].data).expect("parse").marker,
            "talkspurt start propagated"
        );

        // Continuation (no marker) → the marker is not sticky.
        out.clear();
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(3, 0xFF, 160, false)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1);
        assert!(
            !RtpPacket::parse(&out[0].data).expect("parse").marker,
            "marker cleared after one packet"
        );
    }

    #[test]
    fn buffered_talkspurt_marker_rides_to_the_first_full_egress_frame() {
        // A marked ingress frame that only buffers (20 ms into a 40 ms egress) must not lose its
        // talkspurt marker — it rides to the first egress packet that carries the talkspurt start.
        let mut call = ulaw_to_alaw_egress_ptime(40);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(1, 0xFF, 160, true)),
            &mut out,
            &mut events,
        );
        assert!(
            out.is_empty(),
            "marked frame buffered, no egress packet yet"
        );
        call.process(
            &rx(1, A_ADDR, ulaw_rtp_frame(2, 0xFF, 160, false)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1);
        assert!(
            RtpPacket::parse(&out[0].data).expect("parse").marker,
            "the buffered talkspurt marker rides to the first full 40 ms egress packet"
        );
    }

    /// An AMR-WB RTP packet (PT 96) carrying `payload`, with the 16 kHz RTP clock (320 ts units per
    /// 20 ms frame).
    #[cfg(feature = "amr")]
    fn amr_wb_rtp(sequence: u16, payload: &[u8]) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 96,
            sequence,
            timestamp: u32::from(sequence) * 320,
            ssrc: 0x1234_5678,
        };
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    /// The BGCF/SBC PSTN-breakout core: a VoLTE AMR-WB (16 kHz) leg transcoded to a PSTN G.711a
    /// (8 kHz) leg through the media slow path — decode → 16→8 kHz resample → re-encode. Drives the
    /// real `process()` (the same call the live actor makes at run_media_call:1116), so it proves the
    /// transcode+resample chain deterministically, independent of the async datapath. Feature-gated
    /// on `amr` (patent-licensed — docs/codec-licensing.md).
    #[cfg(feature = "amr")]
    #[test]
    fn transcodes_amr_wb_to_g711a_with_resampling() {
        use siphon_rtp_codec::factory::{decoder_for, encoder_for, CodecSpec};

        // Encode 20 ms of 16 kHz PCM into an RFC 4867 octet-aligned AMR-WB payload (VoLTE wire form).
        let mut amr_encoder =
            encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("amr-wb encoder");
        let pcm: Vec<i16> = (0..320)
            .map(|i| ((i as f32 * 0.20).sin() * 6000.0) as i16)
            .collect();
        let mut amr_payload = vec![0u8; 256];
        let written = amr_encoder
            .encode(&pcm, &mut amr_payload)
            .expect("encode amr-wb");
        amr_payload.truncate(written);
        assert!(written > 0, "AMR-WB encoder produced a payload");

        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: decoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20))
                .expect("amr-wb decoder"),
            encoder: encoder_for(&CodecSpec::new(8, "PCMA", 8000, 1, 20)).expect("pcma encoder"),
            egress_ssrc: 0xB000_0008,
            egress_payload_type: 8,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: decoder_for(&CodecSpec::new(8, "PCMA", 8000, 1, 20)).expect("pcma decoder"),
            encoder: encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20))
                .expect("amr-wb encoder"),
            egress_ssrc: 0xA000_0060,
            egress_payload_type: 96,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let mut call = MediaCall::new(
            "amr-call",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        );
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(
            &rx(1, A_ADDR, amr_wb_rtp(1, &amr_payload)),
            &mut out,
            &mut events,
        );

        assert_eq!(out.len(), 1, "one transcoded G.711a packet toward B");
        let datagram = &out[0];
        assert_eq!(
            datagram.endpoint,
            endpoint(2),
            "sent from B's engine socket"
        );
        let packet = RtpPacket::parse(&datagram.data).expect("parse");
        assert_eq!(packet.payload_type, 8, "re-encoded as G.711a (PT 8)");
        assert_eq!(packet.payload.len(), 160, "20 ms at 8 kHz, 1 byte/sample");
        assert_eq!(packet.ssrc, 0xB000_0008, "stamped with the A→B egress SSRC");
        assert!(
            packet.payload.iter().any(|&byte| byte != 0xD5),
            "transcoded G.711a carries non-silence audio"
        );
    }

    /// RFC 4867 §4.3.1: a Codec Mode Request on the A→B stream steers the mode of the AMR-WB stream
    /// the engine sends *back* to A (the b_to_a egress encoder), clamped to any `mode-set`. Proves the
    /// cross-direction wiring in `process()`.
    #[cfg(feature = "amr")]
    #[test]
    fn amr_wb_cmr_steers_the_reverse_direction_encoder() {
        use siphon_rtp_codec::factory::{decoder_for, encoder_for, CodecSpec};

        let amr_dir =
            |ingress: u64, src: &str, egress: u64, dst: &str, ssrc: u32| DirectionConfig {
                ingress_endpoint: endpoint(ingress),
                accepted_source: SourceFilter::Exact(addr(src).ip()),
                egress_endpoint: endpoint(egress),
                egress_dst: addr(dst),
                decoder: decoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("dec"),
                encoder: encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("enc"),
                egress_ssrc: ssrc,
                egress_payload_type: 96,
                telephone_event_in: None,
                telephone_event_out: None,
                recorder: None,
                noise_suppression: false,
                echo_cancellation: false,
                produce_echo_reference: false,
                ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
            };

        // A payload at the default mode 2; flip its CMR nibble to request mode 0 for the B→A stream.
        let mut encoder = encoder_for(&CodecSpec::new(96, "AMR-WB", 16000, 1, 20)).expect("enc");
        let pcm: Vec<i16> = (0..320)
            .map(|i| ((i as f32 * 0.2).sin() * 6000.0) as i16)
            .collect();
        let mut a_payload = vec![0u8; 256];
        let len_a = encoder.encode(&pcm, &mut a_payload).expect("encode");
        a_payload.truncate(len_a);
        a_payload[0] = 0x00; // CMR = 0 (request mode 0)
                             // B's payload carries no request (CMR 15, as emitted).
        let mut b_payload = vec![0u8; 256];
        let len_b = encoder.encode(&pcm, &mut b_payload).expect("encode");
        b_payload.truncate(len_b);

        let mut call = MediaCall::new(
            "cmr",
            "tag-a",
            Some("tag-b".into()),
            amr_dir(1, A_ADDR, 2, B_ADDR, 0xB000_0060),
            amr_dir(2, B_ADDR, 1, A_ADDR, 0xA000_0060),
            true,
            None,
        );
        let mut out = Vec::new();
        let mut events = Vec::new();

        // A→B carries CMR 0 → the toward-A encoder switches to mode 0.
        call.process(
            &rx(1, A_ADDR, amr_wb_rtp(1, &a_payload)),
            &mut out,
            &mut events,
        );
        out.clear();
        // B→A: the reverse egress toward A is now encoded at the requested mode 0.
        call.process(
            &rx(2, B_ADDR, amr_wb_rtp(1, &b_payload)),
            &mut out,
            &mut events,
        );
        assert_eq!(out.len(), 1, "one AMR-WB packet toward A");
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(packet.payload_type, 96, "AMR-WB toward A");
        assert_eq!(
            (packet.payload[1] >> 3) & 0x0F,
            0,
            "toward-A egress adapted to the CMR-requested mode 0"
        );
    }

    /// A minimal RTCP sender-report-shaped datagram (version 2, PT 200) carrying `ssrc` — the shape
    /// [`is_rtcp`] classifies as RTCP and the SRTCP contexts (de)crypt.
    fn rtcp_sr(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0x80, 200, 0x00, 0x00];
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0x33; 16]);
        packet
    }

    #[test]
    fn non_muxed_srtcp_is_relayed_through_the_shared_secure_leg() {
        use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

        // The engine's leg (actor) and the far peer B's leg are key-inverses of one another.
        let engine_key = SrtpKeyMaterial::from_inline_bytes(&[7u8; 30]).expect("engine key");
        let b_key = SrtpKeyMaterial::from_inline_bytes(&[9u8; 30]).expect("b key");
        let actor_leg = Arc::new(Mutex::new(SecureLeg::new(&engine_key, &b_key)));
        let mut peer_leg = SecureLeg::new(&b_key, &engine_key); // stands in for the secure peer B

        // Trivial RTP directions (unused by the RTCP path) on endpoints 1/2; RTCP on 3 (A) / 4 (B).
        let g711 = |ingress: u64, src: &str, egress: u64, dst: &str| DirectionConfig {
            ingress_endpoint: endpoint(ingress),
            accepted_source: SourceFilter::Exact(addr(src).ip()),
            egress_endpoint: endpoint(egress),
            egress_dst: addr(dst),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 0x1111_1111,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let a_rtcp = "127.0.0.2:5001";
        let b_rtcp = "127.0.0.3:6001";
        let relays = vec![
            // A's RTCP (plaintext) → encrypt toward secure B.
            RtcpRelay::new(
                endpoint(3),
                SourceFilter::Exact(addr(a_rtcp).ip()),
                endpoint(4),
                addr(b_rtcp),
            )
            .with_secure_egress(actor_leg.clone()),
            // B's SRTCP → decrypt toward plaintext A.
            RtcpRelay::new(
                endpoint(4),
                SourceFilter::Exact(addr(b_rtcp).ip()),
                endpoint(3),
                addr(a_rtcp),
            )
            .with_secure_ingress(actor_leg.clone()),
        ];
        let mut call = MediaCall::new(
            "srtcp",
            "tag-a",
            Some("tag-b".into()),
            g711(1, A_ADDR, 2, B_ADDR),
            g711(2, B_ADDR, 1, A_ADDR),
            true,
            None,
        )
        .with_far_secure_leg(actor_leg.clone())
        .with_rtcp_relays(relays);
        assert_eq!(call.rtcp_endpoints(), vec![endpoint(3), endpoint(4)]);

        let mut out = Vec::new();
        let mut events = Vec::new();

        // B → A: B encrypts an RTCP SR with its key; the actor decrypts and relays plaintext to A.
        let b_rtcp_plain = rtcp_sr(0xB0B0_B0B0);
        let mut b_srtcp = Vec::new();
        peer_leg
            .protect(&b_rtcp_plain, &mut b_srtcp)
            .expect("peer encrypt SRTCP");
        call.process(&rx(4, b_rtcp, b_srtcp), &mut out, &mut events);
        assert_eq!(out.len(), 1, "one RTCP toward A");
        assert_eq!(out[0].endpoint, endpoint(3));
        assert_eq!(out[0].dst, addr(a_rtcp));
        assert_eq!(
            &out[0].data[..],
            &b_rtcp_plain[..],
            "decrypted plaintext RTCP toward A"
        );

        // A → B: A's plaintext RTCP is encrypted (SRTCP) toward B; the peer recovers it.
        out.clear();
        let a_rtcp_plain = rtcp_sr(0xA0A0_A0A0);
        call.process(&rx(3, a_rtcp, a_rtcp_plain.clone()), &mut out, &mut events);
        assert_eq!(out.len(), 1, "one SRTCP toward B");
        assert_eq!(out[0].endpoint, endpoint(4));
        assert_eq!(out[0].dst, addr(b_rtcp));
        assert_ne!(
            &out[0].data[..],
            &a_rtcp_plain[..],
            "toward B it is encrypted (SRTCP)"
        );
        let mut recovered = Vec::new();
        peer_leg
            .unprotect(&out[0].data, &mut recovered)
            .expect("peer decrypt SRTCP");
        assert_eq!(recovered, a_rtcp_plain, "B recovers A's RTCP");

        // An off-source RTCP is dropped by the RTPBleed gate on the RTCP endpoint.
        out.clear();
        call.process(&rx(4, "127.0.0.9:7000", rtcp_sr(1)), &mut out, &mut events);
        assert!(out.is_empty(), "unsignalled RTCP source dropped");
    }

    #[test]
    fn far_secure_leg_is_exposed_only_for_a_secure_call() {
        use siphon_rtp_srtp::sdes::SrtpKeyMaterial;

        let g711 = |ingress: u64, src: &str, egress: u64, dst: &str| DirectionConfig {
            ingress_endpoint: endpoint(ingress),
            accepted_source: SourceFilter::Exact(addr(src).ip()),
            egress_endpoint: endpoint(egress),
            egress_dst: addr(dst),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 0x1111_1111,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };

        // A plaintext transcode call exposes no secure leg — an HA checkpoint has no SRTP rollover to
        // read (`rollover_snapshot` returns `None`, so `build_secure_media_snapshot` yields no secure
        // section).
        let plain = MediaCall::new(
            "plain",
            "tag-a",
            Some("tag-b".into()),
            g711(1, A_ADDR, 2, B_ADDR),
            g711(2, B_ADDR, 1, A_ADDR),
            true,
            None,
        );
        assert!(
            plain.far_secure_leg().is_none(),
            "a plaintext call has no shared secure leg"
        );

        // A secure-transcode call exposes the *same* shared leg both directions crypt against, so the
        // registry can retain it and checkpoint its rollover after the actor takes ownership.
        let local = SrtpKeyMaterial::from_inline_bytes(&[3u8; 30]).expect("local key");
        let remote = SrtpKeyMaterial::from_inline_bytes(&[4u8; 30]).expect("remote key");
        let leg = Arc::new(Mutex::new(SecureLeg::new(&local, &remote)));
        let secure = MediaCall::new(
            "secure",
            "tag-a",
            Some("tag-b".into()),
            g711(1, A_ADDR, 2, B_ADDR),
            g711(2, B_ADDR, 1, A_ADDR),
            true,
            None,
        )
        .with_far_secure_leg(leg.clone());
        let exposed = secure.far_secure_leg().expect("secure leg exposed");
        assert!(
            Arc::ptr_eq(&exposed, &leg),
            "the exact shared leg instance is returned"
        );
    }

    #[test]
    fn secure_egress_encrypts_relayed_telephone_event() {
        // Regression: a repacketized RFC 4733 telephone-event toward a secure (RTP/SAVP) peer must be
        // encrypted — it previously bypassed `push_egress` and leaked plaintext DTMF on the wire.
        use siphon_rtp_srtp::sdes::SrtpKeyMaterial;
        use siphon_rtp_srtp::SrtpContext;

        let local = SrtpKeyMaterial::from_inline_bytes(&[1u8; 30]).expect("local key");
        let remote = SrtpKeyMaterial::from_inline_bytes(&[2u8; 30]).expect("remote key");
        let leg = Arc::new(Mutex::new(SecureLeg::new(&local, &remote)));

        let direction =
            |ingress: u64, src: &str, egress: u64, dst: &str, ssrc: u32| DirectionConfig {
                ingress_endpoint: endpoint(ingress),
                accepted_source: SourceFilter::Exact(addr(src).ip()),
                egress_endpoint: endpoint(egress),
                egress_dst: addr(dst),
                decoder: Box::new(G711::ulaw()),
                encoder: Box::new(G711::ulaw()),
                egress_ssrc: ssrc,
                egress_payload_type: 0,
                telephone_event_in: Some(101),
                telephone_event_out: Some(101),
                recorder: None,
                noise_suppression: false,
                echo_cancellation: false,
                produce_echo_reference: false,
                ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
            };
        let mut call = MediaCall::new(
            "te",
            "a",
            Some("b".into()),
            direction(1, A_ADDR, 2, B_ADDR, 0xB000_0101), // A→B: plaintext in, secure egress
            direction(2, B_ADDR, 1, A_ADDR, 0xA000_0101),
            true,
            None,
        )
        .with_far_secure_leg(leg);

        // A plaintext telephone-event (PT 101, RFC 4733 4-byte event) from A.
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 160,
            ssrc: 0x1234_5678,
        };
        let mut buffer = vec![0u8; 12 + 4];
        let len = write_packet(&header, &[0x05, 0x0A, 0x01, 0x40], &mut buffer).expect("write");
        buffer.truncate(len);

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, buffer.clone()), &mut out, &mut events);

        let egress = out
            .iter()
            .find(|outbound| outbound.endpoint == endpoint(2))
            .expect("an egress packet toward the secure peer B");
        assert_ne!(
            &egress.data[..],
            &buffer[..],
            "egress must not be the plaintext telephone-event"
        );
        // It is valid SRTP, decryptable with the engine's outbound (local) key to the event packet.
        let mut decrypt = SrtpContext::from_key_material(&local);
        let mut plain = Vec::new();
        decrypt
            .unprotect(&egress.data, &mut plain)
            .expect("egress is valid SRTP");
        let parsed = RtpPacket::parse(&plain).expect("decrypted telephone-event");
        assert_eq!(
            parsed.payload_type, 101,
            "egress is the repacketized telephone-event"
        );
    }

    #[test]
    fn egress_sequence_and_timestamp_advance_per_packet() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0x00)), &mut out, &mut events);
        call.process(&rx(1, A_ADDR, ulaw_rtp(2, 0x00)), &mut out, &mut events);
        let first = RtpPacket::parse(&out[0].data).expect("first");
        let second = RtpPacket::parse(&out[1].data).expect("second");
        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert_eq!(first.timestamp, 0);
        assert_eq!(second.timestamp, 160, "one 8 kHz/20 ms frame");
    }

    #[test]
    fn g722_egress_timestamp_steps_at_8khz_rtp_clock() {
        // A G.722 leg decodes 320 PCM samples per 20 ms frame, but its RTP timestamp clock is
        // 8 kHz (RFC 3551 §4.5.2), so the synthesized egress timestamp must advance by 160 — not
        // 320 — per packet. This proves Phase 0's RTP-clock-vs-native-rate split composes with the
        // codec's `rtp_clock_rate_hz()` end to end through the transcode path.
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G722::new(20)),
            encoder: Box::new(G722::new(20)),
            egress_ssrc: 0xB000_0009,
            egress_payload_type: 9,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Any,
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G722::new(20)),
            encoder: Box::new(G722::new(20)),
            egress_ssrc: 0xA000_0009,
            egress_payload_type: 9,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let mut call = MediaCall::new(
            "g722",
            "tag-a",
            Some("tag-b".into()),
            a_to_b,
            b_to_a,
            true,
            None,
        );
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, g722_rtp(1)), &mut out, &mut events);
        call.process(&rx(1, A_ADDR, g722_rtp(2)), &mut out, &mut events);

        assert_eq!(
            out.len(),
            2,
            "one transcoded G.722 packet per ingress frame"
        );
        let first = RtpPacket::parse(&out[0].data).expect("first");
        let second = RtpPacket::parse(&out[1].data).expect("second");
        assert_eq!(first.payload_type, 9, "re-encoded as G.722 (PT 9)");
        assert_eq!(
            first.payload.len(),
            160,
            "320 PCM samples → 160 G.722 bytes"
        );
        assert_eq!(first.timestamp, 0);
        assert_eq!(
            second.timestamp, 160,
            "G.722 egress advances at the 8 kHz RTP clock (160/frame), not the 320-sample count"
        );
    }

    #[test]
    fn drops_packets_from_an_unsignalled_source() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // An attacker on a different IP sprays A's endpoint — gated out before any transcode.
        call.process(
            &rx(1, "127.0.0.9:5000", ulaw_rtp(1, 0xFF)),
            &mut out,
            &mut events,
        );
        assert!(out.is_empty(), "off-source packet must not be forwarded");
    }

    #[test]
    fn latches_observed_source_for_symmetric_reply() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // B sends from a different *port* than signalled (symmetric NAT). The A→B direction must
        // now target B's observed source. Use the signalled IP so the gate passes.
        let observed = "127.0.0.3:44444";
        call.process(&rx(2, observed, alaw_rtp(1, 0x55)), &mut out, &mut events);
        // Now A sends; its packet should go to B's observed (latched) source.
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        assert_eq!(
            out[0].dst,
            addr(observed),
            "A→B latched to B's observed source"
        );
    }

    fn alaw_rtp(sequence: u16, payload_byte: u8) -> Vec<u8> {
        let header = RtpHeader {
            marker: false,
            payload_type: 8,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 0x8765_4321,
        };
        let payload = [payload_byte; 160];
        let mut buffer = vec![0u8; 12 + payload.len()];
        let len = write_packet(&header, &payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn relays_rtcp_verbatim() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // A minimal RTCP Sender Report (PT 200): version 2, PT 200, length 6.
        let rtcp = vec![0x80, 200, 0x00, 0x06, 0xDE, 0xAD, 0xBE, 0xEF];
        call.process(&rx(1, A_ADDR, rtcp.clone()), &mut out, &mut events);
        assert_eq!(out.len(), 1);
        assert_eq!(&out[0].data[..], &rtcp[..], "RTCP relayed untouched");
        assert_eq!(out[0].endpoint, endpoint(2));
    }

    #[test]
    fn block_suppresses_egress_then_resumes() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.set_blocked(true);
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        assert!(out.is_empty(), "blocked: no egress");
        call.set_blocked(false);
        call.process(&rx(1, A_ADDR, ulaw_rtp(2, 0xFF)), &mut out, &mut events);
        assert_eq!(out.len(), 1, "unblocked: egress resumes");
    }

    #[test]
    fn silence_replaces_audio_with_comfort_silence() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.set_silenced(true);
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0x00)), &mut out, &mut events);
        assert_eq!(out.len(), 1, "silence still emits a packet");
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        // A-law encoding of all-zero PCM is a constant byte; assert it is uniform (comfort silence).
        assert!(packet.payload.iter().all(|&byte| byte == packet.payload[0]));
    }

    #[test]
    fn extracts_dtmf_event_and_repacketizes() {
        let mut call = ulaw_alaw_call();
        let mut out = Vec::new();
        let mut events = Vec::new();
        // RFC 4733 telephone-event payload (PT 101): event 5, End bit set, volume 10, duration 800.
        let event_payload = [5u8, 0x80 | 10, 0x03, 0x20]; // E=1, volume=10, duration=0x0320=800
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 16000,
            ssrc: 0x1111_2222,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);

        call.process(&rx(1, A_ADDR, buffer), &mut out, &mut events);
        assert_eq!(events.len(), 1, "one DTMF event extracted");
        match &events[0] {
            Event::Dtmf {
                digit,
                duration_ms,
                call_id,
                ..
            } => {
                assert_eq!(digit, "5");
                assert_eq!(duration_ms, &100, "800 samples / 8 = 100 ms");
                assert_eq!(call_id, "call-1");
            }
            other => panic!("expected DTMF, got {other:?}"),
        }
        assert_eq!(out.len(), 1, "telephone-event repacketized onto egress");
        let relayed = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(relayed.payload_type, 101);
        assert_eq!(
            relayed.ssrc, 0xB000_0001,
            "stamped with the A→B egress SSRC"
        );
        assert_eq!(relayed.timestamp, 16000, "event RTP timestamp preserved");
    }

    #[test]
    fn echo_reflects_ingress_back_to_the_sender() {
        let mut call = ulaw_alaw_call();
        call.set_echo(true);
        let mut out = Vec::new();
        let mut events = Vec::new();

        // A speaks µ-law toward the engine; with echo on, it must come straight back to A.
        call.process(&rx(1, A_ADDR, ulaw_rtp(100, 0xFF)), &mut out, &mut events);

        assert_eq!(
            out.len(),
            1,
            "exactly one packet, reflected back to the sender"
        );
        let datagram = &out[0];
        assert_eq!(
            datagram.endpoint,
            endpoint(1),
            "echoed out A's own socket, not toward B"
        );
        assert_eq!(datagram.dst, addr(A_ADDR), "echoed back to A's address");
        let packet = RtpPacket::parse(&datagram.data).expect("parse");
        assert_eq!(
            packet.payload_type, 0,
            "re-encoded in A's own codec (µ-law PT 0)"
        );
        assert_eq!(
            packet.ssrc, 0xA000_0001,
            "stamped with the toward-A egress SSRC"
        );
        // Same codec in and out → decode+encode is idempotent, so A hears exactly what it sent.
        assert_eq!(packet.payload, &[0xFFu8; 160][..]);
        assert!(events.is_empty());

        // Toggling echo off restores normal forwarding toward the far leg.
        call.set_echo(false);
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(101, 0x00)), &mut out, &mut events);
        assert_eq!(
            out[0].endpoint,
            endpoint(2),
            "echo off → transcoded toward B again"
        );
    }

    #[test]
    fn echo_still_detects_dtmf_without_echoing_the_tone() {
        let mut call = ulaw_alaw_call();
        call.set_echo(true);
        let mut out = Vec::new();
        let mut events = Vec::new();

        // RFC 4733 '#' (event 11), End bit set — the digit the SBC echo test uses to hang up.
        let event_payload = [11u8, 0x80 | 10, 0x03, 0x20];
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 16000,
            ssrc: 0x1111_2222,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);

        call.process(&rx(1, A_ADDR, buffer), &mut out, &mut events);
        assert_eq!(
            events.len(),
            1,
            "DTMF still surfaces during echo (so '#' can end the test)"
        );
        match &events[0] {
            Event::Dtmf { digit, .. } => assert_eq!(digit, "#"),
            other => panic!("expected DTMF, got {other:?}"),
        }
        assert!(out.is_empty(), "the DTMF tone itself is not echoed back");
    }

    /// Build a single-leg local-answer / IVR call: both directions face caller A on endpoint(1),
    /// µ-law both sides, comfort-idle. `cn_pt` is the negotiated RFC 3389 CN egress payload type (as
    /// `promote_to_processing`'s offer-only branch builds it), or `None` for the audio-noise fallback.
    fn single_leg_call(cn_pt: Option<u8>) -> MediaCall {
        let direction = || DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(1), // faces A — both directions do (single leg)
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 0xA000_0001,
            egress_payload_type: 0,
            telephone_event_in: Some(101),
            telephone_event_out: Some(101),
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        MediaCall::new("ivr", "tag-a", None, direction(), direction(), true, None)
            .with_comfort_idle(cn_pt)
    }

    #[test]
    fn single_leg_handle_does_not_loop_caller_audio_back() {
        // The core fix: a single-leg local answer must never re-encode the caller's decoded ingress
        // back out the caller-facing egress (self-echo). `process` emits nothing from `handle`.
        let mut call = single_leg_call(None);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        assert!(
            out.is_empty(),
            "single-leg handle must not loop the caller's own audio back"
        );
        // The stream still latched (a following comfort tick / prompt targets the observed source).
        assert!(
            call.needs_egress_tick(),
            "single-leg call idles on the playout tick"
        );
    }

    #[test]
    fn single_leg_idle_tick_emits_audio_comfort_noise_when_cn_not_negotiated() {
        // CN not offered ⇒ audio-encoded low-level noise on the leg's own codec (µ-law PT 0), not the
        // constant byte of encoded digital silence, and never the caller's looped audio.
        let mut call = single_leg_call(None);
        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "one comfort-noise packet per idle tick");
        assert_eq!(out[0].endpoint, endpoint(1), "toward the caller");
        assert_eq!(out[0].dst, addr(A_ADDR));
        let (first_seq, first_ts) = {
            let first = RtpPacket::parse(&out[0].data).expect("parse");
            assert_eq!(
                first.payload_type, 0,
                "audio codec (µ-law), CN not negotiated"
            );
            assert_eq!(first.payload.len(), 160, "a full 20 ms G.711 frame");
            assert!(
                !first.payload.iter().all(|&byte| byte == first.payload[0]),
                "comfort noise varies — not the constant byte of encoded silence"
            );
            (first.sequence, first.timestamp)
        };
        // A second tick continues the stream with the sequence/timestamp advancing (continuous).
        out.clear();
        call.tick(&mut out, &mut Vec::new());
        let second = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(second.sequence, first_seq.wrapping_add(1), "seq +1");
        assert_eq!(
            second.timestamp,
            first_ts.wrapping_add(160),
            "ts advances one 8 kHz/20 ms frame"
        );
    }

    #[test]
    fn single_leg_idle_tick_emits_cn_packet_when_negotiated() {
        // CN negotiated (PT 13) ⇒ a 1-byte RFC 3389 CN packet on that PT, sharing the egress SSRC and
        // advancing seq/ts so a following prompt hands over seamlessly.
        let mut call = single_leg_call(Some(13));
        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "one CN packet per idle tick");
        let (first_seq, first_ts) = {
            let first = RtpPacket::parse(&out[0].data).expect("parse");
            assert_eq!(first.payload_type, 13, "RFC 3389 CN payload type");
            assert_eq!(
                first.payload.len(),
                1,
                "a single -dBov level byte (RFC 3389 §3.1)"
            );
            assert_eq!(first.ssrc, 0xA000_0001, "shares the egress SSRC");
            (first.sequence, first.timestamp)
        };
        out.clear();
        call.tick(&mut out, &mut Vec::new());
        let second = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(second.sequence, first_seq.wrapping_add(1), "seq +1");
        assert_eq!(second.timestamp, first_ts.wrapping_add(160), "ts +160");
    }

    #[test]
    fn single_leg_silenced_tick_emits_digital_silence() {
        // `silence_media` (hold/mute) still works on a comfort-idle leg: digital silence (a constant
        // µ-law byte), not comfort noise and not a CN packet.
        let mut call = single_leg_call(Some(13));
        call.set_silenced(true);
        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "silence still emits a continuous stream");
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(
            packet.payload_type, 0,
            "digital silence rides the audio codec"
        );
        assert_eq!(packet.payload.len(), 160);
        assert!(
            packet.payload.iter().all(|&byte| byte == packet.payload[0]),
            "encoded digital silence is a constant byte"
        );
    }

    #[test]
    fn single_leg_player_overrides_comfort_then_resumes() {
        // A prompt overrides the comfort idle; after it drains, comfort resumes — with no self-echo
        // under or after the prompt.
        let mut call = single_leg_call(None);
        // toward_a = false injects on a_to_b (the caller-facing direction), as `start_play` does for a
        // single-leg call.
        call.start_play_audio(false, prompt_player(1), 7, &mut Vec::new());
        assert!(call.has_injection(), "the prompt is active");
        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new());
        // The injection is checked before comfort, so the tick emits exactly the prompt frame (not the
        // prompt *and* a comfort frame). The prompt is a constant 2000-tone → a constant µ-law byte.
        assert_eq!(
            out.len(),
            1,
            "one packet — the prompt, not prompt + comfort"
        );
        assert_eq!(
            RtpPacket::parse(&out[0].data).expect("parse").payload_type,
            0,
            "the prompt plays in the leg's codec"
        );
        // Next tick drains the 1-frame prompt (Completed); the tick after resumes comfort noise.
        out.clear();
        let mut events = Vec::new();
        call.tick(&mut out, &mut events);
        assert_eq!(expect_one_play_finished(&events).0, 7, "prompt completes");
        assert!(!call.has_injection(), "injection cleared");
        out.clear();
        call.tick(&mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "comfort resumes after the prompt");
        let resumed = RtpPacket::parse(&out[0].data).expect("parse");
        assert!(
            !resumed
                .payload
                .iter()
                .all(|&byte| byte == resumed.payload[0]),
            "resumed egress is comfort noise (varies), not a stuck prompt or silence"
        );
    }

    #[test]
    fn single_leg_echo_reflects_and_suppresses_comfort() {
        // The `echo` verb opts into the reflect: `process` loops the caller's audio back (as today),
        // and the idle tick emits no comfort (the two would collide on one SSRC). Disabling echo
        // returns to comfort-idle.
        let mut call = single_leg_call(None);
        call.set_echo(true);
        assert!(
            !call.needs_egress_tick(),
            "no comfort tick while echo reflects"
        );
        let mut out = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(9, 0xFF)), &mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "echo reflects the caller's audio");
        assert_eq!(
            RtpPacket::parse(&out[0].data).expect("parse").payload,
            &[0xFFu8; 160][..],
            "reflected in the caller's own codec (µ-law idempotent)"
        );
        // A tick emits nothing while echo is on.
        out.clear();
        call.tick(&mut out, &mut Vec::new());
        assert!(out.is_empty(), "comfort suppressed during echo");
        // Disable echo → comfort resumes, and process no longer reflects.
        call.set_echo(false);
        assert!(call.needs_egress_tick(), "comfort resumes when echo is off");
        out.clear();
        call.tick(&mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "comfort noise flows again");
    }

    #[test]
    fn single_leg_detects_dtmf_without_echoing_the_tone() {
        // DTMF is still detected on ingress (the SBC collects digits), but the tone is not relayed
        // back to the caller (that would be a self-echo of the caller's own DTMF).
        let mut call = single_leg_call(None);
        let event_payload = [5u8, 0x80 | 10, 0x03, 0x20]; // event 5, End bit, 800-sample duration
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 16000,
            ssrc: 0x1111_2222,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, buffer), &mut out, &mut events);
        assert_eq!(events.len(), 1, "DTMF detected on ingress");
        match &events[0] {
            Event::Dtmf { digit, .. } => assert_eq!(digit, "5"),
            other => panic!("expected DTMF, got {other:?}"),
        }
        assert!(
            out.is_empty(),
            "the caller's own DTMF tone is not echoed back"
        );
    }

    #[test]
    fn play_audio_injects_prompt_in_the_target_legs_codec() {
        use siphon_rtp_media::fanout::MediaSink as _;
        use siphon_rtp_media::player::WavSource;

        let mut call = ulaw_alaw_call();
        // An 8 kHz mono prompt: 320 samples = 40 ms → 2 frames at 20 ms ptime.
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&[2000i16; 320]);
        let wav = recorder.into_wav();
        let source = WavSource::parse(&wav).expect("parse wav");
        let player = PcmPlayer::new(&source, 1, 0);

        call.start_play_audio(true, player, 1, &mut Vec::new()); // toward A (b_to_a egress, µ-law PT 0)
        assert!(call.has_injection());

        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "one prompt packet per playout tick");
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(out[0].endpoint, endpoint(1), "prompt goes out A's socket");
        assert_eq!(
            packet.payload_type, 0,
            "prompt encoded in A's codec (µ-law)"
        );

        // While the prompt plays toward A, B→A transcode is suppressed (A hears the prompt only).
        out.clear();
        call.process(&rx(2, B_ADDR, alaw_rtp(1, 0x55)), &mut out, &mut Vec::new());
        assert!(
            out.is_empty(),
            "transcode toward A is suppressed during playback"
        );

        // Second tick drains the rest; a third finds the prompt exhausted and clears the injection.
        out.clear();
        call.tick(&mut out, &mut Vec::new());
        assert_eq!(out.len(), 1);
        out.clear();
        let mut events = Vec::new();
        call.tick(&mut out, &mut events);
        assert!(
            !call.has_injection(),
            "injection cleared when the prompt ends"
        );
        // The prompt drained on its own → a single PlayFinished{Completed} for play_id 1.
        assert_eq!(
            expect_one_play_finished(&events),
            (1, PlayEndReason::Completed, Some(40)),
            "40 ms prompt (2 frames × 20 ms) completes with its played duration"
        );
    }

    /// Build an 8 kHz mono prompt of `frames` × 20 ms (160 samples/frame) as a fresh `PcmPlayer`.
    fn prompt_player(frames: usize) -> PcmPlayer {
        use siphon_rtp_media::player::WavSource;
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&vec![2000i16; 160 * frames.max(1)]);
        let wav = recorder.into_wav();
        let source = WavSource::parse(&wav).expect("parse wav");
        PcmPlayer::new(&source, 1, 0)
    }

    /// Assert exactly one [`Event::PlayFinished`] was emitted, returning `(play_id, reason,
    /// played_ms)`.
    fn expect_one_play_finished(events: &[Event]) -> (u64, PlayEndReason, Option<u64>) {
        match events {
            [Event::PlayFinished {
                play_id,
                reason,
                played_ms,
                ..
            }] => (*play_id, *reason, *played_ms),
            other => panic!("expected exactly one PlayFinished, got {other:?}"),
        }
    }

    #[test]
    fn play_emits_play_finished_completed_on_drain() {
        let mut call = ulaw_alaw_call();
        // A 2-frame (40 ms) prompt toward A.
        call.start_play_audio(true, prompt_player(2), 7, &mut Vec::new());

        let mut out = Vec::new();
        let mut events = Vec::new();
        // Two ticks emit the two frames; no completion event yet (prompt still playing).
        call.tick(&mut out, &mut events);
        call.tick(&mut out, &mut events);
        assert!(
            events.is_empty(),
            "no PlayFinished while the prompt is still playing"
        );
        // The third tick finds the prompt exhausted, clears the injection, and emits Completed.
        out.clear();
        call.tick(&mut out, &mut events);
        assert!(!call.has_injection(), "injection cleared at end of prompt");
        assert_eq!(
            expect_one_play_finished(&events),
            (7, PlayEndReason::Completed, Some(40)),
            "the prompt drains → PlayFinished{{Completed}} with its play_id and played_ms"
        );
    }

    #[test]
    fn stop_play_emits_play_finished_stopped() {
        let mut call = ulaw_alaw_call();
        call.start_play_audio(true, prompt_player(50), 3, &mut Vec::new()); // a long prompt
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.tick(&mut out, &mut events); // one frame (20 ms) played, prompt far from drained
        assert!(events.is_empty(), "still playing, no completion yet");
        call.stop_play(&mut events);
        assert!(!call.has_injection(), "stop clears the injection");
        assert_eq!(
            expect_one_play_finished(&events),
            (3, PlayEndReason::Stopped, Some(20)),
            "an explicit stop ends the play as Stopped, reporting the 20 ms played so far"
        );
    }

    #[test]
    fn superseding_a_prompt_emits_play_finished_superseded() {
        let mut call = ulaw_alaw_call();
        call.start_play_audio(true, prompt_player(50), 1, &mut Vec::new());
        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new()); // 20 ms of the first prompt played
                                              // A second play on the same direction replaces the first — the old play_id is reported as
                                              // Superseded so a controller awaiting it resolves rather than hanging forever.
        let mut events = Vec::new();
        call.start_play_audio(true, prompt_player(2), 2, &mut events);
        assert_eq!(
            expect_one_play_finished(&events),
            (1, PlayEndReason::Superseded, Some(20)),
            "the superseded prompt is reported for its own play_id, not the new one"
        );
        assert!(call.has_injection(), "the new prompt is now playing");
    }

    #[test]
    fn teardown_emits_play_finished_error_for_an_in_flight_prompt() {
        let mut call = ulaw_alaw_call();
        call.start_play_audio(true, prompt_player(50), 9, &mut Vec::new());
        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new()); // 20 ms played, prompt far from drained
                                              // The leg is torn down mid-play: the actor reports the in-flight prompt as Error so the engine
                                              // (and siphon-sip) can release a controller awaiting it.
        let mut events = Vec::new();
        call.finish_pending_plays(&mut events);
        assert!(!call.has_injection(), "teardown clears the injection");
        assert_eq!(
            expect_one_play_finished(&events),
            (9, PlayEndReason::Error, Some(20)),
            "a torn-down leg ends its prompt as Error"
        );
    }

    #[test]
    fn a_repeated_prompt_emits_play_finished_once_at_the_very_end() {
        use siphon_rtp_media::player::WavSource;
        let mut call = ulaw_alaw_call();
        // A 1-frame (160-sample) body played twice (repeat_times = 2) → 2 frames, then exhausted.
        let mut recorder = WavRecorder::new(8000, 1);
        recorder.write_pcm(&vec![2000i16; 160]);
        let source = WavSource::parse(&recorder.into_wav()).expect("parse");
        let player = PcmPlayer::new(&source, 2, 0);
        call.start_play_audio(true, player, 5, &mut Vec::new());

        let mut out = Vec::new();
        let mut events = Vec::new();
        // The body plays through twice; no completion until every repeat is done.
        call.tick(&mut out, &mut events);
        call.tick(&mut out, &mut events);
        assert!(
            events.is_empty(),
            "no PlayFinished until every repeat has played"
        );
        // The exhaustion tick fires Completed exactly once, reporting both passes (40 ms).
        call.tick(&mut out, &mut events);
        assert_eq!(
            expect_one_play_finished(&events),
            (5, PlayEndReason::Completed, Some(40)),
            "a repeated prompt reports one Completed at the very end"
        );
    }

    #[test]
    fn play_dtmf_injects_telephone_events_toward_the_target() {
        let mut call = ulaw_alaw_call();
        assert!(
            call.start_play_dtmf(true, "5", 100, 10, 40),
            "A negotiated telephone-event"
        );
        let mut out = Vec::new();
        call.tick(&mut out, &mut Vec::new());
        assert_eq!(out.len(), 1);
        let packet = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(packet.payload_type, 101, "egress telephone-event PT");
        assert_eq!(packet.payload[0], 5, "RFC 4733 event code for '5'");
        assert!(
            packet.marker,
            "first packet of the event carries the marker"
        );
    }

    #[test]
    fn play_dtmf_plays_a_multi_digit_code_as_distinct_events() {
        // A multi-digit code "12" injects one RFC 4733 event per digit: event code 1 then 2, each
        // opening with the marker, the second event's timestamp advanced past the first, and an
        // inter-digit gap (no telephone-event) between them. The injection clears when the code drains.
        let mut call = ulaw_alaw_call();
        assert!(call.start_play_dtmf(true, "12", 100, 10, 40));

        let mut first_event_timestamp = None;
        let mut second_event_timestamp = None;
        let mut saw_gap_after_first = false;
        // Tick well past the whole sequence (2×(5 update + 3 End) + 2 gap ticks = 18) and drain it.
        for _ in 0..40 {
            let mut out = Vec::new();
            call.tick(&mut out, &mut Vec::new());
            for outbound in &out {
                let packet = RtpPacket::parse(&outbound.data).expect("parse");
                assert_eq!(packet.payload_type, 101, "egress telephone-event PT");
                match packet.payload[0] {
                    1 => {
                        if packet.marker {
                            first_event_timestamp = Some(packet.timestamp);
                        }
                    }
                    2 => {
                        if packet.marker {
                            second_event_timestamp = Some(packet.timestamp);
                        }
                    }
                    other => panic!("unexpected DTMF event code {other}"),
                }
            }
            // Once the first digit's marker was seen, a later tick that emits nothing is the gap.
            if first_event_timestamp.is_some() && second_event_timestamp.is_none() && out.is_empty()
            {
                saw_gap_after_first = true;
            }
        }
        let first = first_event_timestamp.expect("digit 1 played");
        let second = second_event_timestamp.expect("digit 2 played");
        assert!(
            second.wrapping_sub(first) > 0,
            "the second digit event starts at a later RTP timestamp"
        );
        assert!(
            saw_gap_after_first,
            "an inter-digit silence gap separated the events"
        );
        assert!(
            !call.has_injection(),
            "the sequence cleared when the code drained"
        );
    }

    #[test]
    fn play_dtmf_fails_without_a_negotiated_telephone_event() {
        // A direction with no egress telephone-event PT cannot carry DTMF.
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Any,
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 1,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Any,
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 2,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let mut call = MediaCall::new("c", "a", None, a_to_b, b_to_a, true, None);
        assert!(
            !call.start_play_dtmf(true, "5", 100, 10, 40),
            "no telephone-event ⇒ cannot inject"
        );
    }

    #[test]
    fn a_fork_emits_rtp_alongside_the_transcoded_egress() {
        use siphon_rtp_media::fork::RtpForkSink;

        // Fork leg A's decoded audio to a subscriber as µ-law (PT 0, SSRC 0xFEED_F00D), while A→B
        // still transcodes to A-law. One ingress packet ⇒ one transcoded egress AND one forked RTP.
        let mut call = ulaw_alaw_call();
        let (fork_tx, fork_rx) = flume::bounded(8);
        let sink = RtpForkSink::new(Box::new(G711::ulaw()), fork_tx, 0xFEED_F00D, 0);
        call.add_fork(true, Box::new(sink));
        assert_eq!(call.fork_count(true), 1);

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(100, 0x40)), &mut out, &mut events);

        // The normal transcoded packet toward B is undisturbed (A-law, PT 8, the A→B egress SSRC).
        assert_eq!(out.len(), 1, "one transcoded packet toward B");
        let egress = RtpPacket::parse(&out[0].data).expect("egress parse");
        assert_eq!(egress.payload_type, 8, "B still gets A-law");
        assert_eq!(egress.ssrc, 0xB000_0001);

        // The fork received a well-formed RTP packet with the subscriber's PT/SSRC.
        let forked_bytes = fork_rx.try_recv().expect("one forked packet");
        let forked = RtpPacket::parse(&forked_bytes).expect("fork parse");
        assert_eq!(forked.payload_type, 0, "fork re-encoded as µ-law (PT 0)");
        assert_eq!(
            forked.ssrc, 0xFEED_F00D,
            "fork stamped with the subscriber SSRC"
        );
        assert_eq!(forked.sequence, 0, "fork egress sequence starts at 0");
        assert_eq!(forked.payload.len(), 160);

        // A second ingress packet advances the fork's egress sequence independently of the A→B stream.
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(101, 0x40)), &mut out, &mut events);
        let second_bytes = fork_rx.try_recv().expect("second forked packet");
        let second = RtpPacket::parse(&second_bytes).expect("parse");
        assert_eq!(second.sequence, 1, "fork sequence advances per frame");
    }

    #[test]
    fn remove_fork_stops_forwarding_and_keeps_transcode() {
        use siphon_rtp_media::fork::RtpForkSink;

        let mut call = ulaw_alaw_call();
        let (fork_tx, fork_rx) = flume::bounded(8);
        call.add_fork(
            true,
            Box::new(RtpForkSink::new(Box::new(G711::ulaw()), fork_tx, 7, 0)),
        );

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0x40)), &mut out, &mut events);
        assert!(fork_rx.try_recv().is_ok(), "fork forwarded while attached");

        call.remove_forks(true);
        assert_eq!(call.fork_count(true), 0);
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(2, 0x40)), &mut out, &mut events);
        assert_eq!(
            out.len(),
            1,
            "transcode toward B continues after the fork is removed"
        );
        assert!(
            fork_rx.try_recv().is_err(),
            "no more forked packets after remove"
        );
    }

    /// A single RFC 4733 telephone-event RTP packet on PT 101 (digit 5, end bit set) — the fixture
    /// the DTMF tests share. `marker` starts the event, `end` sets the RFC 4733 end bit. `timestamp`
    /// keys the detector's event boundary — each distinct value is a fresh event (RFC 4733 §2.5.1.2).
    fn telephone_event_rtp(sequence: u16, timestamp: u32, marker: bool, end: bool) -> Vec<u8> {
        // event=5, E-bit per `end`, volume 10, duration 0x0320. RFC 4733 §2.3 payload layout.
        let event_payload = [5u8, ((end as u8) << 7) | 10, 0x03, 0x20];
        let header = RtpHeader {
            marker,
            payload_type: 101,
            sequence,
            timestamp,
            ssrc: 0x1111_2222,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn block_dtmf_drops_telephone_event_relay_but_still_emits_the_event() {
        // On a transcoding call, a telephone-event from A with dtmf_blocked is NOT relayed to B
        // (no egress telephone-event), but the control-plane Event::Dtmf still fires (observability).
        // Clearing the block restores the relay.
        let mut call = ulaw_alaw_call();
        call.set_dtmf_blocked(true, true); // block A's DTMF toward B

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(
            &rx(1, A_ADDR, telephone_event_rtp(1, 16000, true, true)),
            &mut out,
            &mut events,
        );
        assert_eq!(
            events.len(),
            1,
            "DTMF still detected + emitted while blocked"
        );
        assert!(
            matches!(&events[0], Event::Dtmf { digit, .. } if digit == "5"),
            "the digit is surfaced to the controller"
        );
        assert!(
            out.is_empty(),
            "no telephone-event relayed to B while dtmf_blocked"
        );

        // Unblock: a fresh event (new RTP timestamp) now repacketizes toward B again.
        call.set_dtmf_blocked(true, false);
        out.clear();
        events.clear();
        call.process(
            &rx(1, A_ADDR, telephone_event_rtp(2, 17600, true, true)),
            &mut out,
            &mut events,
        );
        assert_eq!(events.len(), 1, "still detected after unblock");
        assert_eq!(out.len(), 1, "telephone-event relayed to B after unblock");
        let relayed = RtpPacket::parse(&out[0].data).expect("parse");
        assert_eq!(relayed.payload_type, 101, "egress telephone-event PT");
    }

    #[test]
    fn block_dtmf_on_a_relay_drops_telephone_events_by_pt_but_forwards_ordinary_rtp() {
        // A promoted plain relay with dtmf_blocked drops the verbatim forward of the leg's
        // telephone-event PT (still emitting the event) but forwards ordinary RTP untouched.
        let mut call = relay_call();
        assert!(call.is_relay_only());
        call.set_dtmf_blocked(true, true); // block A's DTMF toward B

        // Ordinary audio RTP (PT 0) still relays byte-for-byte.
        let audio = ulaw_rtp(1, 0xAB);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, audio.clone()), &mut out, &mut events);
        assert_eq!(out.len(), 1, "ordinary RTP still forwarded verbatim");
        assert_eq!(&out[0].data[..], &audio[..], "forwarded byte-for-byte");
        assert!(events.is_empty(), "no DTMF event for ordinary audio");

        // A telephone-event on PT 101 is dropped (not forwarded) but the event fires.
        out.clear();
        events.clear();
        call.process(
            &rx(1, A_ADDR, telephone_event_rtp(2, 16000, true, true)),
            &mut out,
            &mut events,
        );
        assert!(
            out.is_empty(),
            "telephone-event dropped on the blocked relay leg"
        );
        assert_eq!(
            events.len(),
            1,
            "DTMF still detected + emitted on the relay path"
        );

        // Unblock: a fresh telephone-event (new RTP timestamp) is forwarded verbatim again.
        call.set_dtmf_blocked(true, false);
        out.clear();
        events.clear();
        let event = telephone_event_rtp(3, 17600, true, true);
        call.process(&rx(1, A_ADDR, event.clone()), &mut out, &mut events);
        assert_eq!(
            out.len(),
            1,
            "telephone-event forwarded again after unblock"
        );
        assert_eq!(
            &out[0].data[..],
            &event[..],
            "forwarded byte-for-byte after unblock"
        );
    }

    #[test]
    fn a_fork_does_not_disturb_dtmf_extraction() {
        use siphon_rtp_media::fork::RtpForkSink;

        // A telephone-event packet is handled out of band (no decode), so the fork sees nothing, and
        // the DTMF event + repacketization are unchanged with a fork attached (regression guard).
        let mut call = ulaw_alaw_call();
        let (fork_tx, fork_rx) = flume::bounded(8);
        call.add_fork(
            true,
            Box::new(RtpForkSink::new(Box::new(G711::ulaw()), fork_tx, 9, 0)),
        );

        let event_payload = [5u8, 0x80 | 10, 0x03, 0x20];
        let header = RtpHeader {
            marker: true,
            payload_type: 101,
            sequence: 1,
            timestamp: 16000,
            ssrc: 0x1111_2222,
        };
        let mut buffer = vec![0u8; 16];
        let len = write_packet(&header, &event_payload, &mut buffer).expect("write");
        buffer.truncate(len);

        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, buffer), &mut out, &mut events);
        assert_eq!(events.len(), 1, "DTMF still extracted with a fork attached");
        assert_eq!(out.len(), 1, "telephone-event still repacketized");
        assert!(
            fork_rx.try_recv().is_err(),
            "the fork only sees decoded audio, not DTMF"
        );
    }

    fn tee(subscriber: u64, srs: &str) -> RawTee {
        RawTee {
            subscriber_endpoint: endpoint(subscriber),
            srs_dst: addr(srs),
        }
    }

    #[test]
    fn raw_tee_copies_leg_a_original_rtp_byte_for_byte_alongside_transcode() {
        // SIPREC raw tee: leg A's ORIGINAL ingress RTP is copied verbatim to the subscriber while the
        // A→B transcode (µ-law → A-law) continues. No re-encode — the SRS sees exactly what A sent.
        let mut call = ulaw_alaw_call();
        call.add_raw_tee(true, tee(99, "127.0.0.9:7000"));
        assert_eq!(call.raw_tee_count(true), 1);

        let original = ulaw_rtp(100, 0x40);
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, original.clone()), &mut out, &mut events);

        // Two outbound: the raw tee (emitted first) and the transcoded packet toward B.
        assert_eq!(out.len(), 2, "one raw tee + one transcoded egress");
        let teed = out
            .iter()
            .find(|o| o.endpoint == endpoint(99))
            .expect("tee outbound");
        assert_eq!(teed.dst, addr("127.0.0.9:7000"), "tee goes to the SRS");
        assert_eq!(
            &teed.data[..],
            &original[..],
            "SRS receives A's ORIGINAL RTP byte-for-byte"
        );
        let to_b = out
            .iter()
            .find(|o| o.endpoint == endpoint(2))
            .expect("transcoded egress");
        let parsed = RtpPacket::parse(&to_b.data).expect("parse");
        assert_eq!(
            parsed.payload_type, 8,
            "B still gets A-law (genuinely transcoded)"
        );
    }

    #[test]
    fn raw_tee_tees_rtcp_and_dtmf_verbatim_too() {
        // The raw tee copies whatever arrives — RTP, RTCP, telephone-event — so the SRS records the
        // leg's actual media stream untouched (RFC 7866 §6).
        let mut call = ulaw_alaw_call();
        call.add_raw_tee(true, tee(99, "127.0.0.9:7000"));

        // An RTCP Sender Report on leg A.
        let rtcp = vec![0x80u8, 200, 0x00, 0x06, 0xDE, 0xAD, 0xBE, 0xEF];
        let mut out = Vec::new();
        call.process(&rx(1, A_ADDR, rtcp.clone()), &mut out, &mut Vec::new());
        let teed = out
            .iter()
            .find(|o| o.endpoint == endpoint(99))
            .expect("tee");
        assert_eq!(&teed.data[..], &rtcp[..], "RTCP tee'd verbatim");
    }

    #[test]
    fn remove_raw_tee_stops_only_the_named_subscriber() {
        // Two subscribers tap leg A; removing one leaves the other intact (MPTY / multi-SRS).
        let mut call = ulaw_alaw_call();
        call.add_raw_tee(true, tee(91, "127.0.0.9:7000"));
        call.add_raw_tee(true, tee(92, "127.0.0.9:8000"));
        assert_eq!(call.raw_tee_count(true), 2);

        call.remove_raw_tee(true, endpoint(91));
        assert_eq!(call.raw_tee_count(true), 1);

        let mut out = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0x40)), &mut out, &mut Vec::new());
        assert!(
            out.iter().all(|o| o.endpoint != endpoint(91)),
            "removed subscriber gets nothing"
        );
        assert!(
            out.iter().any(|o| o.endpoint == endpoint(92)),
            "the other subscriber still tee'd"
        );
    }

    /// A relay-only call (a promoted passthrough leg): both directions forward verbatim, no codecs.
    fn relay_call() -> MediaCall {
        let a_to_b = RelayConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            telephone_event: Some(101),
        };
        let b_to_a = RelayConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            telephone_event: Some(101),
        };
        MediaCall::new_relay("relay", "tag-a", Some("tag-b".into()), a_to_b, b_to_a, true)
    }

    #[test]
    fn relay_only_forwards_ingress_verbatim_to_the_peer() {
        // A promoted passthrough relay forwards the ingress RTP byte-for-byte to the peer (no encode).
        let mut call = relay_call();
        assert!(call.is_relay_only());
        let original = ulaw_rtp(7, 0xAB);
        let mut out = Vec::new();
        call.process(&rx(1, A_ADDR, original.clone()), &mut out, &mut Vec::new());
        assert_eq!(out.len(), 1, "one verbatim forward toward B");
        assert_eq!(out[0].endpoint, endpoint(2), "forwarded out B's socket");
        assert_eq!(out[0].dst, addr(B_ADDR));
        assert_eq!(&out[0].data[..], &original[..], "forwarded byte-for-byte");
    }

    /// Build a redirected datagram with an explicit arrival time (the capture timestamp).
    fn rx_at(endpoint_id: u64, source: &str, arrival: u64, data: Vec<u8>) -> RxPacket {
        RxPacket {
            endpoint: endpoint(endpoint_id),
            source: addr(source),
            arrival,
            data: Bytes::from(data),
        }
    }

    #[test]
    fn recording_captures_accepted_ingress_on_both_legs_with_the_5_tuple() {
        let mut call = relay_call();
        let (sender, sink) = flume::bounded(16);
        call.start_recording(PcapCapture {
            sender,
            a_local: addr("127.0.0.1:10000"),
            b_local: addr("127.0.0.1:10002"),
        });
        assert!(call.is_recording());

        // A→B accepted packet: captured with A's observed source, leg A's engine-local destination,
        // the verbatim RTP bytes, and the arrival timestamp.
        let a_packet = ulaw_rtp(1, 0x40);
        call.process(
            &rx_at(1, A_ADDR, 123, a_packet.clone()),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        let captured = sink.try_recv().expect("A→B datagram captured");
        assert_eq!(
            captured.source,
            addr(A_ADDR),
            "captured source = A's observed addr"
        );
        assert_eq!(
            captured.destination,
            addr("127.0.0.1:10000"),
            "captured destination = leg A's engine-local addr"
        );
        assert_eq!(
            &captured.payload[..],
            &a_packet[..],
            "RTP captured byte-for-byte"
        );
        assert_eq!(
            captured.timestamp_micros, 123,
            "arrival timestamp propagated"
        );

        // B→A accepted packet is captured with leg B's local address.
        let b_packet = alaw_rtp(1, 0x55);
        call.process(
            &rx_at(2, B_ADDR, 456, b_packet.clone()),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        let captured = sink.try_recv().expect("B→A datagram captured");
        assert_eq!(
            captured.destination,
            addr("127.0.0.1:10002"),
            "captured destination = leg B's engine-local addr"
        );
        assert_eq!(captured.timestamp_micros, 456);

        // An off-source packet is gated out *before* capture — the recording never sees it.
        call.process(
            &rx_at(1, "127.0.0.99:5000", 789, ulaw_rtp(2, 0xFF)),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert!(
            sink.try_recv().is_err(),
            "off-source packet is gated before capture"
        );

        // After stop_recording, nothing more is captured.
        call.stop_recording();
        assert!(!call.is_recording());
        call.process(
            &rx_at(1, A_ADDR, 1000, ulaw_rtp(3, 0x41)),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert!(sink.try_recv().is_err(), "no capture after stop_recording");
    }

    #[test]
    fn relay_only_gates_off_source_and_tees_to_the_srs() {
        let mut call = relay_call();
        call.add_raw_tee(true, tee(99, "127.0.0.9:7000"));

        // Off-source packet on leg A is gated out (RTPBleed defence) — no forward, no tee.
        let mut out = Vec::new();
        call.process(
            &rx(1, "127.0.0.99:5000", ulaw_rtp(1, 0xFF)),
            &mut out,
            &mut Vec::new(),
        );
        assert!(
            out.is_empty(),
            "off-source packet dropped before forward or tee"
        );

        // A signalled packet forwards to B AND tees to the SRS.
        let original = ulaw_rtp(2, 0x40);
        out.clear();
        call.process(&rx(1, A_ADDR, original.clone()), &mut out, &mut Vec::new());
        let to_b = out
            .iter()
            .find(|o| o.endpoint == endpoint(2))
            .expect("relay to B");
        assert_eq!(&to_b.data[..], &original[..], "relayed verbatim to B");
        let teed = out
            .iter()
            .find(|o| o.endpoint == endpoint(99))
            .expect("tee to SRS");
        assert_eq!(&teed.data[..], &original[..], "tee'd verbatim to the SRS");
    }

    #[test]
    fn relay_only_latches_the_observed_source_for_the_reverse_direction() {
        // B replies from an unexpected port (symmetric NAT); the A→B direction latches it.
        let mut call = relay_call();
        let observed = "127.0.0.3:55555";
        let mut out = Vec::new();
        call.process(
            &rx(2, observed, alaw_rtp(1, 0x55)),
            &mut out,
            &mut Vec::new(),
        );
        out.clear();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut Vec::new());
        assert_eq!(
            out[0].dst,
            addr(observed),
            "A→B latched to B's observed source"
        );
    }

    #[test]
    fn relay_only_block_suppresses_the_forward_but_still_tees() {
        // Block on a promoted relay suppresses the peer forward; the SRS still records the held leg.
        let mut call = relay_call();
        call.add_raw_tee(true, tee(99, "127.0.0.9:7000"));
        call.set_blocked(true);
        let mut out = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut Vec::new());
        assert!(
            out.iter().all(|o| o.endpoint != endpoint(2)),
            "blocked: no forward to B"
        );
        assert!(
            out.iter().any(|o| o.endpoint == endpoint(99)),
            "but the SRS still gets the media"
        );
    }

    #[test]
    fn records_decoded_audio_when_configured() {
        // A recorder on the A→B direction captures A's decoded audio.
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(G711::ulaw()),
            encoder: Box::new(L16::new(8000, 20)),
            egress_ssrc: 1,
            egress_payload_type: 11,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: Some(WavRecorder::new(8000, 1)),
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Any,
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(L16::new(8000, 20)),
            encoder: Box::new(G711::ulaw()),
            egress_ssrc: 2,
            egress_payload_type: 0,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let mut call = MediaCall::new(
            "rec-call",
            "a",
            None,
            a_to_b,
            b_to_a,
            true,
            Some("/tmp".to_string()),
        );
        let mut out = Vec::new();
        let mut events = Vec::new();
        call.process(&rx(1, A_ADDR, ulaw_rtp(1, 0xFF)), &mut out, &mut events);
        let files = call.take_recordings();
        assert_eq!(files.len(), 1, "one direction recorded");
        assert!(files[0].0.ends_with("rec-call-a.wav"));
        assert!(files[0].1.starts_with(b"RIFF"), "valid WAV header");
    }

    /// An L16↔L16 (lossless) 8 kHz call with noise suppression on the A→B direction only, so an
    /// NS-off run is an exact passthrough and the egress energy comparison isolates the suppressor.
    fn ns_l16_call(noise_suppression: bool) -> MediaCall {
        let a_to_b = DirectionConfig {
            ingress_endpoint: endpoint(1),
            accepted_source: SourceFilter::Exact(addr(A_ADDR).ip()),
            egress_endpoint: endpoint(2),
            egress_dst: addr(B_ADDR),
            decoder: Box::new(L16::new(8000, 20)),
            encoder: Box::new(L16::new(8000, 20)),
            egress_ssrc: 0xB000_0002,
            egress_payload_type: 11,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        let b_to_a = DirectionConfig {
            ingress_endpoint: endpoint(2),
            accepted_source: SourceFilter::Exact(addr(B_ADDR).ip()),
            egress_endpoint: endpoint(1),
            egress_dst: addr(A_ADDR),
            decoder: Box::new(L16::new(8000, 20)),
            encoder: Box::new(L16::new(8000, 20)),
            egress_ssrc: 0xA000_0002,
            egress_payload_type: 11,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: false,
            produce_echo_reference: false,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        MediaCall::new("ns-call", "a", None, a_to_b, b_to_a, false, None)
    }

    /// An L16 RTP packet (PT 11) carrying one 20 ms PCM frame.
    fn l16_rtp(sequence: u16, pcm: &[i16]) -> Vec<u8> {
        use siphon_rtp_codec::Encoder as _;
        let mut encoder = L16::new(8000, 20);
        let mut payload = [0u8; MAX_RTP];
        let payload_len = encoder.encode(pcm, &mut payload).expect("encode L16");
        let header = RtpHeader {
            marker: false,
            payload_type: 11,
            sequence,
            timestamp: u32::from(sequence) * 160,
            ssrc: 0x1234_5678,
        };
        let mut buffer = vec![0u8; 12 + payload_len];
        let written = write_packet(&header, &payload[..payload_len], &mut buffer).expect("write");
        buffer.truncate(written);
        buffer
    }

    #[test]
    fn noise_suppression_attenuates_noise_through_the_media_path() {
        use siphon_rtp_codec::Decoder as _;

        // Deterministic white-noise PCM frames (160 samples @ 8 kHz), identical for both runs.
        let mut state = 0x1234_5678u32;
        let mut noise_sample = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (((state >> 8) as f32 / (1u32 << 24) as f32) - 0.5) * 2.0 * 2000.0
        };
        let frame_count = 200usize;
        let frames: Vec<Vec<i16>> = (0..frame_count)
            .map(|_| (0..160).map(|_| noise_sample() as i16).collect())
            .collect();

        // Total decoded egress energy toward B over the converged region (past the WOLA startup).
        let egress_energy = |noise_suppression: bool| -> f64 {
            let mut call = ns_l16_call(noise_suppression);
            let mut decoder = L16::new(8000, 20);
            let mut energy = 0.0f64;
            for (index, frame) in frames.iter().enumerate() {
                let mut out = Vec::new();
                let mut events = Vec::new();
                call.process(
                    &rx(1, A_ADDR, l16_rtp(index as u16, frame)),
                    &mut out,
                    &mut events,
                );
                if index < 30 {
                    continue; // let the suppressor's noise floor and WOLA converge first
                }
                for datagram in &out {
                    if datagram.endpoint != endpoint(2) {
                        continue;
                    }
                    let packet = RtpPacket::parse(&datagram.data).expect("parse egress");
                    let mut pcm = [0i16; MAX_PCM];
                    let count = decoder
                        .decode(packet.payload, &mut pcm)
                        .expect("decode egress");
                    energy += pcm[..count]
                        .iter()
                        .map(|&sample| f64::from(sample) * f64::from(sample))
                        .sum::<f64>();
                }
            }
            energy
        };

        let off = egress_energy(false);
        let on = egress_energy(true);
        assert!(off > 0.0, "sanity: NS-off passes the noise through");
        // The suppressor removes the bulk of stationary noise on the converged region.
        assert!(
            on < 0.7 * off,
            "noise suppression must attenuate through the pipeline: on {on:.3e} vs off {off:.3e}"
        );
    }

    /// An L16 ↔ L16 (lossless linear-PCM) transcoding call for the ERLE measurement. When `aec` is set,
    /// **only the A→B direction cancels** (A's uplink echo), reading the B→A egress toward A as its
    /// reference; the B→A direction merely *produces* that reference ring (it does not cancel). Driving
    /// a single direction's canceller isolates the cross-direction reference path under test from the
    /// artificial feedback a symmetric echo-only bench would create (in a real call the two references
    /// are different, uncorrelated talkers). L16 makes the decode → re-encode round-trip bit-exact, so
    /// the measured A→B egress is the canceller's true residual — no codec quantization masking the ERLE.
    fn aec_l16_call(aec: bool) -> MediaCall {
        let direction = |ingress: u64,
                         src: &str,
                         egress: u64,
                         dst: &str,
                         ssrc: u32,
                         cancel: bool,
                         produce: bool| DirectionConfig {
            ingress_endpoint: endpoint(ingress),
            accepted_source: SourceFilter::Exact(addr(src).ip()),
            egress_endpoint: endpoint(egress),
            egress_dst: addr(dst),
            decoder: Box::new(L16::new(8000, 20)),
            encoder: Box::new(L16::new(8000, 20)),
            egress_ssrc: ssrc,
            egress_payload_type: 11,
            telephone_event_in: None,
            telephone_event_out: None,
            recorder: None,
            noise_suppression: false,
            echo_cancellation: cancel,
            produce_echo_reference: produce,
            ingress_mos_codec: siphon_rtp_hep::mos::Codec::G711,
        };
        MediaCall::new(
            "aec-call",
            "a",
            Some("b".into()),
            // A→B cancels A's uplink; B→A produces the reference toward A but does not cancel.
            direction(1, A_ADDR, 2, B_ADDR, 0xB000_0003, aec, false),
            direction(2, B_ADDR, 1, A_ADDR, 0xA000_0003, false, aec),
            true,
            None,
        )
    }

    #[test]
    fn echo_cancellation_reduces_uplink_echo_on_the_transcode_datapath() {
        // End-to-end proof that the cross-direction reference is wired and the canceller runs on
        // `MediaCall::process`. A committed white far-end stream F is what the engine sends toward A
        // (party B forwards it, so the `b_to_a` egress toward A carries F, captured as A's far-end
        // reference). Party A's uplink is a *pure echo* of F — F convolved with a fixed sparse RIR at a
        // bulk delay, near-end talker silent — so the transcoded egress toward B is the residual echo.
        // With echo cancellation enabled the residual must fall by a large ERLE margin versus an
        // identical AEC-off call (whose egress is the echo unchanged, since L16 is lossless).
        const FRAMES: usize = 500;
        const FRAME: usize = 160; // 20 ms @ 8 kHz
        const DELAY: usize = 24; // bulk echo-path delay (samples), recovered by GCC-PHAT / spanned by the tail
                                 // A fixed, committed room/line impulse response: a few decaying taps (deterministic, no clock).
                                 // Kept below ~0.5 total gain (ERL ≈ 12 dB, the hands-free norm) so the echo never trips the
                                 // canceller's Geigel double-talk pre-screen — a louder-than-far echo would look like near-end.
        const RIR: [f32; 7] = [0.20, 0.0, -0.10, 0.0, 0.05, 0.0, -0.025];

        // Committed white far-end stream (LCG, fixed seed). White ⇒ the reverse direction cannot predict
        // F from the (delayed, correlated-only-at-lag) residual, so the reference toward A stays clean.
        let mut state = 0x0EC0_1234u32;
        let mut noise = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            ((state >> 8) as f32 / (1u32 << 23) as f32 - 1.0) * 6000.0
        };
        let total = FRAMES * FRAME;
        let far: Vec<i16> = (0..total).map(|_| noise() as i16).collect();
        // echo[i] = Σ_k RIR[k] · far[i − DELAY − k] (the near-end mic signal, near-end talker silent).
        let echo: Vec<i16> = (0..total)
            .map(|i| {
                let mut acc = 0.0f32;
                for (k, &tap) in RIR.iter().enumerate() {
                    if let Some(idx) = i.checked_sub(DELAY + k) {
                        acc += tap * f32::from(far[idx]);
                    }
                }
                acc.round().clamp(-32768.0, 32767.0) as i16
            })
            .collect();

        // Drive one call and return (Σ echo², Σ residual²) over the converged tail (second half).
        let run = |aec: bool| -> (f64, f64) {
            let mut call = aec_l16_call(aec);
            let mut decoder = L16::new(8000, 20);
            let mut out = Vec::new();
            let mut events = Vec::new();
            let (mut echo_energy, mut residual_energy) = (0.0f64, 0.0f64);
            for frame in 0..FRAMES {
                let window = frame * FRAME..(frame + 1) * FRAME;
                // B forwards the clean far-end F[t] → `b_to_a` egress toward A carries it (the reference).
                out.clear();
                events.clear();
                call.process(
                    &rx(2, B_ADDR, l16_rtp(frame as u16, &far[window.clone()])),
                    &mut out,
                    &mut events,
                );
                // A's uplink = pure echo of F. `a_to_b` cancels it against `b_to_a`'s reference (F[t]).
                out.clear();
                events.clear();
                call.process(
                    &rx(1, A_ADDR, l16_rtp(frame as u16, &echo[window.clone()])),
                    &mut out,
                    &mut events,
                );
                if frame < FRAMES / 2 {
                    continue; // convergence lead-in (delay lock + MDF settle)
                }
                for datagram in &out {
                    if datagram.endpoint != endpoint(2) {
                        continue; // only the a_to_b egress toward B is the residual
                    }
                    let Ok(packet) = RtpPacket::parse(&datagram.data) else {
                        continue;
                    };
                    let mut pcm = [0i16; MAX_PCM];
                    let Ok(count) = decoder.decode(packet.payload, &mut pcm) else {
                        continue;
                    };
                    for &value in &pcm[..count] {
                        residual_energy += f64::from(value) * f64::from(value);
                    }
                }
                for &value in &echo[window] {
                    echo_energy += f64::from(value) * f64::from(value);
                }
            }
            (echo_energy, residual_energy)
        };

        let (echo_on, residual_on) = run(true);
        let (echo_off, residual_off) = run(false);
        // Sanity: the far-end really produced echo, and AEC-off forwards it essentially unchanged
        // (L16 is lossless, so the egress echo energy ≈ the input echo energy).
        assert!(
            echo_on > 0.0 && residual_off > 0.0,
            "the uplink must carry echo"
        );
        let erle_off = 10.0 * (echo_off / residual_off).log10();
        let erle_on = 10.0 * (echo_on / residual_on).log10();
        assert!(
            erle_off.abs() < 1.0,
            "AEC off must forward the echo unchanged (ERLE ≈ 0), got {erle_off:.1} dB"
        );
        assert!(
            erle_on >= 20.0,
            "echo cancellation did not run on the datapath: ERLE on {erle_on:.1} dB \
             (off {erle_off:.1} dB); residual on {residual_on:.0} vs off {residual_off:.0}"
        );
    }
}
