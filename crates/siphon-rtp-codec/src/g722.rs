//! G.722 sub-band ADPCM (ITU-T G.722), 64 kbit/s — wideband HD voice, RTP payload type 9.
//!
//! G.722 codes 16 kHz audio as two 8 kHz sub-bands: a 24-tap QMF splits the signal into a low band
//! (0–4 kHz, 6-bit ADPCM, 48 kbit/s) and a high band (4–8 kHz, 2-bit ADPCM, 16 kbit/s), packed into
//! one byte per **two** input samples → 64 kbit/s (ITU-T G.722 §3). Only **mode 1** (64 kbit/s) is
//! implemented; modes 2/3 (56/48 kbit/s, which steal low-band bits for an auxiliary data channel)
//! are not used on SIP and would mis-decode here, so the codec exposes mode 1 exclusively.
//!
//! ## RTP clock quirk
//! G.722 samples 16 kHz audio but, for historical reasons, clocks its RTP timestamps at **8 kHz**
//! (RFC 3551 §4.5.2). [`CodecParams::sample_rate_hz`] is the native 16 kHz rate (the decoded PCM
//! rate); [`Encoder::rtp_clock_rate_hz`] reports 8 kHz so the media path advances RTP timestamps
//! correctly (320 PCM samples / 20 ms but a timestamp step of 160).
//!
//! ## Statefulness
//! Unlike the stateless G.711, a `G722` instance carries adaptive predictor/scale state and a QMF
//! delay line. Encode and decode are **separate** signal chains, so one instance is used as *either*
//! an encoder *or* a decoder, never both — the [`crate::factory`] builds a distinct instance for each
//! direction. A round-trip test therefore uses two instances.
//!
//! The fixed-point arithmetic (tables, shifts, saturation, predictor update order) reproduces the
//! ITU-T reference exactly; every block carries its ITU-T G.722 block name (`QUANTL`, `SCALEL`,
//! `UPPOL2`, …) so the next reader can check it against the Recommendation.

use crate::{CodecError, CodecParams, Decoder, Encoder};

// ---- Constant tables (ITU-T G.722 §3) ---------------------------------------------------------

/// The 12 distinct QMF coefficients; the 24-tap QMF applies `QMF_COEFFS[i]` and `QMF_COEFFS[11-i]`
/// across the even/odd taps (ITU-T G.722 §3.1, transmit/receive QMF).
const QMF_COEFFS: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];

/// Low-band 6-bit quantizer decision levels (encoder, QUANTL — ITU-T G.722 §3.4).
const Q6: [i32; 32] = [
    0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940,
    1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0,
];
/// Low-band codeword for a negative difference (encoder, QUANTL).
const ILN: [i32; 32] = [
    0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4, 0,
];
/// Low-band codeword for a non-negative difference (encoder, QUANTL).
const ILP: [i32; 32] = [
    0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32, 0,
];
/// Low-band log-scale-factor increments (LOGSCL — ITU-T G.722 §3.5).
const WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
/// Low-band code → coarse (4-bit) index map (RL42).
const RL42: [i32; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
/// Log-scale-factor → linear scale table, shared by both bands (SCALEL/SCALEH — ITU-T G.722 §3.5).
const ILB: [i32; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];
/// Low-band 4-bit inverse quantizer — drives the predictor difference in every mode (INVQAL).
const QM4: [i32; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];
/// Low-band 6-bit inverse quantizer — reconstructs the decoded sample in mode 1 (INVQBL, 64 kbit/s).
const QM6: [i32; 64] = [
    -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192, -10232,
    -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576, -3168, -2776,
    -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704, 14984, 13512, 12280,
    11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944, 4464, 4008, 3576, 3168, 2776,
    2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
];
/// High-band codeword for a negative difference (encoder, QUANTH; 1-based index).
const IHN: [i32; 3] = [0, 1, 0];
/// High-band codeword for a non-negative difference (encoder, QUANTH; 1-based index).
const IHP: [i32; 3] = [0, 3, 2];
/// High-band log-scale-factor increments (LOGSCH).
const WH: [i32; 3] = [0, -214, 798];
/// High-band code → coarse index map (RH2).
const RH2: [i32; 4] = [2, 1, 2, 1];
/// High-band 2-bit inverse quantizer (INVQAH).
const QM2: [i32; 4] = [-7408, -1616, 7408, 1616];

/// Clamp an `i32` accumulator to the signed-16-bit range (ITU-T G.722 `saturate`).
#[inline]
fn saturate(value: i32) -> i32 {
    value.clamp(i16::MIN as i32, i16::MAX as i32)
}

/// One sub-band's adaptive ADPCM state (predictor + scale factor). `band[0]` is the low band,
/// `band[1]` the high band; the layout is identical for both. Field names follow the ITU-T G.722
/// reference variables so the update steps map onto the Recommendation block-by-block.
#[derive(Debug, Clone)]
struct Band {
    /// Predictor output `s = sp + sz` (PREDIC).
    s: i32,
    /// Pole-predictor output (FILTEP).
    sp: i32,
    /// Zero-predictor output (FILTEZ).
    sz: i32,
    /// Log scale factor (LOGSCL/LOGSCH).
    nb: i32,
    /// Linear scale factor (SCALEL/SCALEH).
    det: i32,
    /// Reconstructed-signal history `r[0..=2]`.
    r: [i32; 3],
    /// Pole coefficients `a[1], a[2]` (`a[0]` unused).
    a: [i32; 3],
    /// Partially-reconstructed-signal history `p[0..=2]` (PARREC).
    p: [i32; 3],
    /// Difference-signal history `d[0..=6]`.
    d: [i32; 7],
    /// Zero (FIR) coefficients `b[1..=6]` (`b[0]` unused).
    b: [i32; 7],
}

impl Band {
    /// A zeroed band with the ITU-T initial linear scale factor `det` (low band 32, high band 8).
    const fn new(det: i32) -> Self {
        Self {
            s: 0,
            sp: 0,
            sz: 0,
            nb: 0,
            det,
            r: [0; 3],
            a: [0; 3],
            p: [0; 3],
            d: [0; 7],
            b: [0; 7],
        }
    }

    /// The shared predictor update run once per band per sample-pair with the band's reconstructed
    /// difference `d` (ITU-T G.722 §3.6: RECONS → PARREC → UPPOL2 → UPPOL1 → UPZERO → DELAYA →
    /// FILTEP → FILTEZ → PREDIC, in that order — the ordering is load-bearing for bit-exactness).
    fn block4(&mut self, difference: i32) {
        let mut ap = [0i32; 3];
        let mut bp = [0i32; 7];
        let mut sg = [0i32; 7];

        // RECONS
        self.d[0] = difference;
        self.r[0] = saturate(self.s + difference);
        // PARREC
        self.p[0] = saturate(self.sz + difference);

        // UPPOL2 — second pole coefficient
        for (sign, &partial) in sg.iter_mut().zip(self.p.iter()).take(3) {
            *sign = partial >> 15;
        }
        let mut wd1 = saturate(self.a[1] << 2);
        let mut wd2 = if sg[0] == sg[1] { -wd1 } else { wd1 };
        if wd2 > 32767 {
            wd2 = 32767; // one-sided clamp only (ITU-T G.722)
        }
        let mut wd3 = (wd2 >> 7) + if sg[0] == sg[2] { 128 } else { -128 };
        wd3 += (self.a[2] * 32512) >> 15;
        wd3 = wd3.clamp(-12288, 12288);
        ap[2] = wd3;

        // UPPOL1 — first pole coefficient
        sg[0] = self.p[0] >> 15;
        sg[1] = self.p[1] >> 15;
        wd1 = if sg[0] == sg[1] { 192 } else { -192 };
        wd2 = (self.a[1] * 32640) >> 15;
        ap[1] = saturate(wd1 + wd2);
        wd3 = saturate(15360 - ap[2]);
        ap[1] = ap[1].clamp(-wd3, wd3);

        // UPZERO — six zero coefficients
        let leak = if difference == 0 { 0 } else { 128 };
        sg[0] = difference >> 15;
        for i in 1..7 {
            sg[i] = self.d[i] >> 15;
            let term = if sg[i] == sg[0] { leak } else { -leak };
            bp[i] = saturate(term + ((self.b[i] * 32640) >> 15));
        }

        // DELAYA — shift the signal histories and commit the updated coefficients
        self.d.copy_within(0..6, 1);
        self.b[1..7].copy_from_slice(&bp[1..7]);
        self.r.copy_within(0..2, 1);
        self.p.copy_within(0..2, 1);
        self.a[1..3].copy_from_slice(&ap[1..3]);

        // FILTEP — pole predictor
        wd1 = (self.a[1] * saturate(self.r[1] + self.r[1])) >> 15;
        wd2 = (self.a[2] * saturate(self.r[2] + self.r[2])) >> 15;
        self.sp = saturate(wd1 + wd2);

        // FILTEZ — zero predictor (accumulate the six taps in i32, saturate only the sum)
        let mut sz = 0i32;
        for i in 1..7 {
            sz += (self.b[i] * saturate(self.d[i] + self.d[i])) >> 15;
        }
        self.sz = saturate(sz);

        // PREDIC
        self.s = saturate(self.sp + self.sz);
    }

    /// Derive the linear scale factor `det` from the log scale factor `nb` (SCALEL/SCALEH). `shift`
    /// is the band-specific constant (8 for the low band, 10 for the high band).
    #[inline]
    fn scale(&mut self, shift: i32) {
        let index = ((self.nb >> 6) & 31) as usize;
        let amount = shift - (self.nb >> 11);
        let scaled = if amount < 0 {
            ILB[index] << ((-amount) as u32)
        } else {
            ILB[index] >> (amount as u32)
        };
        self.det = scaled << 2;
    }
}

/// A G.722 codec instance (used as *either* a [`Decoder`] *or* an [`Encoder`] — see the module docs).
#[derive(Debug, Clone)]
pub struct G722 {
    params: CodecParams,
    /// QMF delay line (24 samples) — analysis on encode, synthesis on decode.
    qmf_history: [i32; 24],
    /// Low-band and high-band ADPCM state.
    band: [Band; 2],
}

impl G722 {
    /// Create a G.722 codec at the given packetization time (16 kHz mono, 64 kbit/s mode 1).
    #[must_use]
    pub fn new(ptime_ms: u8) -> Self {
        Self {
            params: CodecParams {
                sample_rate_hz: 16_000,
                channels: 1,
                ptime_ms: ptime_ms.max(1),
            },
            qmf_history: [0; 24],
            // ITU-T G.722 init: only the linear scale factors are non-zero (low 32, high 8).
            band: [Band::new(32), Band::new(8)],
        }
    }

    /// The codec's native parameters (16 kHz, mono).
    #[must_use]
    pub fn params(&self) -> CodecParams {
        self.params
    }

    /// Native PCM samples in one packetization interval (e.g. 320 at 20 ms).
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    /// Encode one pair of 16 kHz samples into one G.722 code byte (mode 1).
    fn encode_pair(&mut self, first: i16, second: i16) -> u8 {
        // QMF analysis (transmit QMF): newest pair enters the delay line, split into two bands.
        self.qmf_history.copy_within(2.., 0);
        self.qmf_history[22] = i32::from(first);
        self.qmf_history[23] = i32::from(second);
        let mut sum_odd = 0i32;
        let mut sum_even = 0i32;
        for i in 0..12 {
            sum_odd += self.qmf_history[2 * i] * QMF_COEFFS[i];
            sum_even += self.qmf_history[2 * i + 1] * QMF_COEFFS[11 - i];
        }
        let xlow = (sum_even + sum_odd) >> 14;
        let xhigh = (sum_even - sum_odd) >> 14;
        self.encode_subband(xlow, xhigh)
    }

    /// Encode one (low, high) sub-band sample pair into a G.722 code byte — the QMF-free ADPCM core
    /// (ITU-T G.722 §3.4–3.6). Shared by [`G722::encode_pair`] (after QMF analysis) and the ITU
    /// Appendix II conformance test (which drives this core with the QMF bypassed, configuration 1).
    fn encode_subband(&mut self, xlow: i32, xhigh: i32) -> u8 {
        // --- Low band: QUANTL → INVQAL → LOGSCL → SCALEL → block4 ---
        let low = &mut self.band[0];
        let el = saturate(xlow - low.s);
        let magnitude = if el >= 0 { el } else { -(el + 1) };
        let mut interval = 1usize;
        while interval < 30 {
            if magnitude < (Q6[interval] * low.det) >> 12 {
                break;
            }
            interval += 1;
        }
        let ilow = if el < 0 { ILN[interval] } else { ILP[interval] };
        let coarse = (ilow >> 2) as usize; // top 4 bits → INVQAL / LOGSCL index
        let dlow = (low.det * QM4[coarse]) >> 15;
        low.nb = ((low.nb * 127) >> 7) + WL[RL42[coarse] as usize];
        low.nb = low.nb.clamp(0, 18432);
        low.scale(8);
        low.block4(dlow);

        // --- High band: QUANTH → INVQAH → LOGSCH → SCALEH → block4 ---
        let high = &mut self.band[1];
        let eh = saturate(xhigh - high.s);
        let magnitude = if eh >= 0 { eh } else { -(eh + 1) };
        let mih = if magnitude >= (564 * high.det) >> 12 { 2 } else { 1 };
        let ihigh = if eh < 0 { IHN[mih] } else { IHP[mih] };
        let dhigh = (high.det * QM2[ihigh as usize]) >> 15;
        high.nb = ((high.nb * 127) >> 7) + WH[RH2[ihigh as usize] as usize];
        high.nb = high.nb.clamp(0, 22528);
        high.scale(10);
        high.block4(dhigh);

        // Pack: bits 7..6 = high-band code (2 bits), bits 5..0 = low-band code (6 bits).
        ((ihigh << 6) | ilow) as u8
    }

    /// Decode one G.722 code byte (mode 1) into two 16 kHz samples.
    fn decode_byte(&mut self, code: u8) -> (i16, i16) {
        let (rlow, rhigh) = self.decode_subband(code);
        // QMF synthesis (receive QMF): recombine the two bands into two 16 kHz output samples.
        self.qmf_history.copy_within(2.., 0);
        self.qmf_history[22] = rlow + rhigh;
        self.qmf_history[23] = rlow - rhigh;
        let mut out_odd = 0i32;
        let mut out_even = 0i32;
        for i in 0..12 {
            out_even += self.qmf_history[2 * i] * QMF_COEFFS[i];
            out_odd += self.qmf_history[2 * i + 1] * QMF_COEFFS[11 - i];
        }
        (saturate(out_odd >> 11) as i16, saturate(out_even >> 11) as i16)
    }

    /// Decode one G.722 code byte into the (low, high) reconstructed sub-band samples — the QMF-free
    /// ADPCM core. Shared by [`G722::decode_byte`] (before QMF synthesis) and the ITU Appendix II
    /// conformance test (configuration 2). Returns the limited 14-bit `(rlow, rhigh)`.
    fn decode_subband(&mut self, code: u8) -> (i32, i32) {
        let code = i32::from(code);
        let low_code = code & 0x3F; // 6-bit low-band code
        let ihigh = (code >> 6) & 0x03; // 2-bit high-band code
        let coarse = (low_code >> 2) as usize; // top 4 bits → predictor path

        // --- Low band: INVQBL+RECONS → LIMIT → INVQAL → LOGSCL → SCALEL → block4 ---
        let low = &mut self.band[0];
        let reconstructed = (low.det * QM6[low_code as usize]) >> 15;
        let rlow = (low.s + reconstructed).clamp(-16384, 16383);
        let dlow = (low.det * QM4[coarse]) >> 15; // coarse difference drives the predictor
        low.nb = ((low.nb * 127) >> 7) + WL[RL42[coarse] as usize];
        low.nb = low.nb.clamp(0, 18432);
        low.scale(8);
        low.block4(dlow);

        // --- High band: INVQAH+RECONS → LIMIT → LOGSCH → SCALEH → block4 ---
        let high = &mut self.band[1];
        let dhigh = (high.det * QM2[ihigh as usize]) >> 15;
        let rhigh = (dhigh + high.s).clamp(-16384, 16383);
        high.nb = ((high.nb * 127) >> 7) + WH[RH2[ihigh as usize] as usize];
        high.nb = high.nb.clamp(0, 22528);
        high.scale(10);
        high.block4(dhigh);

        (rlow, rhigh)
    }
}

impl Decoder for G722 {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    fn decode(&mut self, payload: &[u8], out: &mut [i16]) -> Result<usize, CodecError> {
        let samples = payload.len() * 2; // two 16 kHz samples per code byte
        if out.len() < samples {
            return Err(CodecError::OutputTooSmall {
                needed: samples,
                have: out.len(),
            });
        }
        for (i, &code) in payload.iter().enumerate() {
            let (first, second) = self.decode_byte(code);
            out[2 * i] = first;
            out[2 * i + 1] = second;
        }
        Ok(samples)
    }

    fn conceal(&mut self, out: &mut [i16]) -> Result<usize, CodecError> {
        // Basic PLC: comfort silence (the floor the project mandates). A waveform-extrapolation
        // concealment (G.722 Appendix III/IV) is a later refinement; silence is artifact-free for
        // short gaps. The adaptive state is intentionally left untouched.
        let count = self.frame_samples().min(out.len());
        out[..count].fill(0);
        Ok(count)
    }
}

impl Encoder for G722 {
    fn params(&self) -> CodecParams {
        self.params
    }

    fn frame_samples(&self) -> usize {
        self.params.frame_samples()
    }

    fn encode(&mut self, pcm: &[i16], out: &mut [u8]) -> Result<usize, CodecError> {
        let bytes = pcm.len() / 2; // one code byte per two input samples
        if out.len() < bytes {
            return Err(CodecError::OutputTooSmall {
                needed: bytes,
                have: out.len(),
            });
        }
        for (byte, pair) in out.iter_mut().zip(pcm.chunks_exact(2)) {
            *byte = self.encode_pair(pair[0], pair[1]);
        }
        Ok(bytes)
    }

    /// G.722 clocks RTP timestamps at 8 kHz despite its 16 kHz audio (RFC 3551 §4.5.2).
    fn rtp_clock_rate_hz(&self) -> u32 {
        8_000
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    /// 20 ms of 16 kHz audio.
    const FRAME: usize = 320;

    #[test]
    fn reports_native_16k_but_8k_rtp_clock() {
        let codec = G722::new(20);
        assert_eq!(codec.params().sample_rate_hz, 16_000, "native PCM rate");
        assert_eq!(codec.frame_samples(), FRAME, "320 samples per 20 ms");
        // The RTP timestamp clock is the historical 8 kHz, not the native rate (RFC 3551 §4.5.2).
        assert_eq!(Encoder::rtp_clock_rate_hz(&codec), 8_000);
    }

    #[test]
    fn encode_produces_one_byte_per_two_samples() {
        let mut codec = G722::new(20);
        let pcm = vec![0i16; FRAME];
        let mut out = vec![0u8; FRAME / 2];
        assert_eq!(codec.encode(&pcm, &mut out).expect("encode"), FRAME / 2);
    }

    #[test]
    fn decode_produces_two_samples_per_byte() {
        let mut codec = G722::new(20);
        let payload = vec![0u8; FRAME / 2];
        let mut out = vec![0i16; FRAME];
        assert_eq!(codec.decode(&payload, &mut out).expect("decode"), FRAME);
    }

    #[test]
    fn encode_rejects_small_output() {
        let mut codec = G722::new(20);
        let pcm = [0i16; FRAME];
        let mut out = [0u8; 10];
        assert_eq!(
            codec.encode(&pcm, &mut out),
            Err(CodecError::OutputTooSmall {
                needed: 160,
                have: 10
            })
        );
    }

    #[test]
    fn decode_rejects_small_output() {
        let mut codec = G722::new(20);
        let payload = [0u8; 160];
        let mut out = [0i16; 10];
        assert_eq!(
            codec.decode(&payload, &mut out),
            Err(CodecError::OutputTooSmall {
                needed: 320,
                have: 10
            })
        );
    }

    #[test]
    fn conceal_writes_silence() {
        let mut codec = G722::new(20);
        let mut out = [123i16; FRAME];
        assert_eq!(codec.conceal(&mut out).expect("conceal"), FRAME);
        assert!(out.iter().all(|&s| s == 0));
    }

    #[test]
    fn encode_is_deterministic_across_fresh_instances() {
        let pcm: Vec<i16> = (0..FRAME).map(|k| ((k as i32 * 211) % 4000 - 2000) as i16).collect();
        let mut a = vec![0u8; FRAME / 2];
        let mut b = vec![0u8; FRAME / 2];
        G722::new(20).encode(&pcm, &mut a).expect("a");
        G722::new(20).encode(&pcm, &mut b).expect("b");
        assert_eq!(a, b, "deterministic, no hidden global state");
    }

    /// Build a band-limited test signal (tones inside the G.722 50–7000 Hz passband).
    fn band_limited(n: usize) -> Vec<i16> {
        (0..n)
            .map(|k| {
                let t = k as f64 / 16_000.0;
                let v = 0.30 * (2.0 * PI * 300.0 * t).sin()
                    + 0.30 * (2.0 * PI * 1200.0 * t).sin()
                    + 0.20 * (2.0 * PI * 2500.0 * t).sin();
                (v * 10_000.0) as i16
            })
            .collect()
    }

    #[test]
    fn roundtrip_reconstructs_band_limited_signal() {
        let n = 4000;
        let input = band_limited(n);

        let mut encoder = G722::new(20);
        let mut payload = vec![0u8; n / 2];
        encoder.encode(&input, &mut payload).expect("encode");

        let mut decoder = G722::new(20);
        let mut output = vec![0i16; n];
        decoder.decode(&payload, &mut output).expect("decode");

        // The QMF introduces a small group delay; align on the best integer lag, then measure SNR
        // over the steady-state region (skip the startup transient and leave lag headroom).
        let region = 500..(n - 64);
        let signal: f64 = region.clone().map(|k| f64::from(input[k]).powi(2)).sum();
        let mut best_snr = f64::NEG_INFINITY;
        for lag in 0..48usize {
            let error: f64 = region
                .clone()
                .map(|k| (f64::from(input[k]) - f64::from(output[k + lag])).powi(2))
                .sum();
            if error > 0.0 {
                best_snr = best_snr.max(10.0 * (signal / error).log10());
            }
        }
        // G.722 at 64 kbit/s reconstructs the passband faithfully; >20 dB segmental SNR is a wide
        // margin that still proves the full QMF + sub-band ADPCM chain works end to end.
        assert!(best_snr > 20.0, "round-trip SNR too low: {best_snr:.1} dB");
    }

    fn vector_path(name: &str) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../reference/g722/testv");
        path.push(name);
        path
    }

    /// Parse an ITU-T G.722 Appendix II ASCII-hex test sequence: skip `/* */` comment lines, then
    /// read 16-bit words as 4-hex-char groups (MSB-first), stopping at each line's trailing checksum.
    fn parse_itu_hex(bytes: &[u8]) -> Vec<u16> {
        let text = String::from_utf8_lossy(bytes);
        let mut words = Vec::new();
        for line in text.lines() {
            if line.starts_with("/*") {
                continue;
            }
            let bytes = line.as_bytes();
            let mut k = 0;
            while k + 4 <= bytes.len() {
                match std::str::from_utf8(&bytes[k..k + 4])
                    .ok()
                    .and_then(|g| u16::from_str_radix(g, 16).ok())
                {
                    Some(word) => {
                        words.push(word);
                        k += 4;
                    }
                    None => break,
                }
            }
        }
        words
    }

    /// The active (non-reset) word range. The ITU sequences bracket the payload with reset words
    /// whose LSB is 1 (Appendix II): skip the leading run, stop at the trailing run.
    fn active_range(words: &[u16]) -> std::ops::Range<usize> {
        let start = words.iter().position(|w| w & 1 == 0).unwrap_or(words.len());
        let end = words[start..]
            .iter()
            .position(|w| w & 1 == 1)
            .map_or(words.len(), |p| p + start);
        start..end
    }

    #[test]
    fn itu_appendix_ii_conformance_mode1() {
        // Bit-exact ITU-T G.722 Appendix II conformance, mode 1 (64 kbit/s), with the QMF bypassed
        // (configurations 1 & 2 — the QMF is validated separately by round-trip SNR, exactly as the
        // ITU procedure intends). This is the official acceptance criterion for the SB-ADPCM core.
        // Vectors are gitignored / LFS-pending, so skip gracefully when absent.
        let load = |name: &str| std::fs::read(vector_path(name)).ok().map(|b| parse_itu_hex(&b));
        let Some(t1c1) = load("T1C1.XMT") else {
            eprintln!("ITU G.722 Appendix II vectors absent — skipping conformance test");
            return;
        };

        // Encoder (configuration 1): input PCM word → xlow = xhigh = word >> 1 → one code; the
        // reference code is the upper byte of each T2R*.COD word.
        let encode_case = |xmt: &[u16], cod: &[u16]| {
            assert_eq!(xmt.len(), cod.len(), "encode vector length mismatch");
            let mut codec = G722::new(20);
            for k in active_range(xmt) {
                let xband = i32::from(xmt[k] as i16) >> 1;
                let got = codec.encode_subband(xband, xband);
                let want = ((cod[k] >> 8) & 0xFF) as u8;
                assert_eq!(got, want, "encoder mismatch at word {k}");
            }
        };
        encode_case(&t1c1, &load("T2R1.COD").expect("T2R1.COD"));
        if let (Some(x), Some(c)) = (load("T1C2.XMT"), load("T2R2.COD")) {
            encode_case(&x, &c);
        }

        // Decoder (configuration 2): code (upper byte) → (rlow, rhigh) → rlow<<1 (lower band) and
        // rhigh<<1 (higher band), compared to the T3L*.RC1 / T3H*.RC0 references.
        let decode_case = |cod: &[u16], lower: &[u16], upper: &[u16]| {
            assert_eq!(cod.len(), lower.len(), "decode lower length mismatch");
            assert_eq!(cod.len(), upper.len(), "decode upper length mismatch");
            let mut codec = G722::new(20);
            for k in active_range(cod) {
                let code = ((cod[k] >> 8) & 0xFF) as u8;
                let (rlow, rhigh) = codec.decode_subband(code);
                assert_eq!((rlow << 1) as i16, lower[k] as i16, "decoder lower mismatch at word {k}");
                assert_eq!((rhigh << 1) as i16, upper[k] as i16, "decoder upper mismatch at word {k}");
            }
        };
        decode_case(
            &load("T2R1.COD").expect("T2R1.COD"),
            &load("T3L1.RC1").expect("T3L1.RC1"),
            &load("T3H1.RC0").expect("T3H1.RC0"),
        );
        if let (Some(c), Some(l), Some(h)) = (load("T1D3.COD"), load("T3L3.RC1"), load("T3H3.RC0")) {
            decode_case(&c, &l, &h);
        }
    }

    #[test]
    fn roundtrip_silence_decodes_near_zero() {
        // True digital silence (zero PCM) encoded then decoded reconstructs near-silence: the
        // adaptive scale factors shrink toward the quantization-noise floor rather than buzzing.
        // (Note: an all-`0x00` *code* stream is NOT silence — code 0 is the outer quantizer level.)
        let n = 1600;
        let mut encoder = G722::new(20);
        let mut payload = vec![0u8; n / 2];
        encoder.encode(&vec![0i16; n], &mut payload).expect("encode");
        let mut decoder = G722::new(20);
        let mut out = vec![0i16; n];
        decoder.decode(&payload, &mut out).expect("decode");
        // After the brief startup transient the reconstructed silence stays quiet (< -42 dBFS).
        assert!(
            out[400..].iter().all(|&s| s.unsigned_abs() < 256),
            "silence round-trip not quiet: peak {}",
            out[400..].iter().map(|s| s.unsigned_abs()).max().unwrap_or(0)
        );
    }

    #[test]
    fn decodes_arbitrary_bytes_without_panicking() {
        // G.722 decode has no framing to malform — every byte is a valid code — but a hostile or
        // truncated stream must still decode-or-error: never panic, index out of bounds, or
        // overflow. This stands in for a fuzz target (the fixed byte→samples transform has no
        // parser to fuzz; `saturate` bounds every intermediate to the 16-bit range).
        let mut decoder = G722::new(20);
        let payload: Vec<u8> = (0..2048u32)
            .map(|k| (k.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let mut out = vec![0i16; payload.len() * 2];
        let produced = decoder.decode(&payload, &mut out).expect("decode fills a full buffer");
        assert_eq!(produced, payload.len() * 2);
        // A too-small buffer errors rather than writing out of bounds.
        let mut tiny = [0i16; 3];
        assert!(decoder.decode(&payload, &mut tiny).is_err());
    }
}
