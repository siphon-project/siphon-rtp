//! CELT-only **mono float** decode orchestration (RFC 6716 §4.3; libopus
//! `celt/celt_decoder.c` `celt_decode_with_ec_dred` + `celt_synthesis`, `#ifndef FIXED_POINT`).
//!
//! **Phase 3 (assembly).** Every sub-component — range coder, band-energy decode, tf-resolution,
//! bit allocation, recursive band/PVQ decode, anti-collapse, inverse MDCT, comb post-filter,
//! de-emphasis — already lives in its own module and is validated against the libopus float build.
//! This module is the glue: a [`CeltDecoder`] state struct holding the persistent decoder fields
//! (`CELTDecoder` in `celt_decoder.c:87`) and a decode entry point that drives those pieces in the
//! exact order libopus does, with the exact 1/8-bit (`BITRES`) bit-budget arguments.
//!
//! Scope is deliberately narrow, matching the task: **mono (`C = 1`), CELT-only, valid data packet**.
//! All `ENABLE_QEXT` (quality-extension), `ENABLE_DEEP_PLC` (neural PLC), and packet-loss / PLC
//! branches of the C are stripped — the caller (the Opus packet/mode dispatcher) is responsible for
//! framing, mode selection, and loss concealment. The float decoder conforms via the `opus_compare`
//! tolerance metric, not bit-exact PCM (RFC 6716 §6), so this is a faithful float port.
//!
//! Line references below cite `celt/celt_decoder.c` from the libopus tree the port was made against.

use crate::opus::celt::anti_collapse::anti_collapse;
use crate::opus::celt::band_coder::quant_all_bands;
use crate::opus::celt::energy::{
    unquant_coarse_energy, unquant_energy_finalise, unquant_fine_energy,
};
use crate::opus::celt::mdct::{clt_mdct_backward, MdctLookup};
use crate::opus::celt::postfilter::{comb_filter, COMBFILTER_MINPERIOD};
use crate::opus::celt::rate::{clt_compute_allocation, init_caps};
use crate::opus::celt::synthesis::{deemphasis, denormalise_bands, float_to_i16};
use crate::opus::celt::tables::{
    BITRES, E_BANDS, MAX_LM, NB_BANDS, OVERLAP, PREEMPH, SHORT_MDCT_SIZE, SPREAD_ICDF,
    SPREAD_NORMAL, TAPSET_ICDF, TRIM_ICDF, WINDOW120,
};
use crate::opus::celt::tf::tf_decode;
use crate::opus::packet::Bandwidth;
use crate::opus::range_coder::RangeDecoder;
use crate::CodecError;

/// Decode ring length per channel (libopus `DECODE_BUFFER_SIZE`, `celt_decoder.c:79` →
/// `DEC_PITCH_BUF_SIZE` = 2048). The per-channel buffer is `DECODE_BUFFER_SIZE + overlap` long.
const DECODE_BUFFER_SIZE: usize = 2048;

/// Total per-channel decode-ring length (`DECODE_BUFFER_SIZE + mode->overlap`).
const DECODE_MEM_LEN: usize = DECODE_BUFFER_SIZE + OVERLAP;

/// The 48 kHz CELT mode is always mono here (`C = CC = 1`).
const CHANNELS: usize = 1;

/// Base inverse-MDCT length for the 48 kHz mode (libopus `mode->mdct.n`). This is `2 *
/// shortMdctSize * nbShortMdcts = 2 * 120 * 8` — twice the long-frame sample count, because the MDCT
/// is a 50 %-overlapping transform (an N-sample frame is reconstructed by an MDCT of length 2N). The
/// `mdct.rs` docs require `MdctLookup::new(1920, 3)`.
const MDCT_BASE_LEN: usize = 1920;

/// Largest CELT frame in samples: `shortMdctSize << MAX_LM` = 960 (20 ms at 48 kHz).
const MAX_FRAME_SAMPLES: usize = SHORT_MDCT_SIZE << MAX_LM;

/// `-28 dB` in the log2 energy domain (libopus `-GCONST(28.f)`), the reset value for the energy
/// history (`celt_decoder.c:1810`).
const ENERGY_RESET_DB: f32 = -28.0;

/// Persistent CELT decoder state (libopus `struct CELTDecoder`, `celt_decoder.c:87`, mono float — the
/// `DECODER_RESET_START` block plus the MDCT lookup and the cleared decode ring). Stereo, QEXT, PLC,
/// and LPC fields are omitted (out of scope for the mono CELT-only path).
pub struct CeltDecoder {
    /// Inverse-MDCT / FFT lookup for the 48 kHz mode (`mode->mdct`, base length 1920, shifts 0..=3).
    mdct: MdctLookup,
    /// Previous frame's per-band log2 energy, `2*NB_BANDS` (`oldBandE`). Channel `c`'s band `i` is
    /// at `i + c*NB_BANDS`; the inter-frame coarse-energy predictor reads/writes it.
    old_band_energy: [f32; 2 * NB_BANDS],
    /// Energy one frame back (`oldLogE`); reset to `-28 dB`.
    old_log_energy: [f32; 2 * NB_BANDS],
    /// Energy two frames back (`oldLogE2`); reset to `-28 dB`. Feeds anti-collapse `Ediff`.
    old_log_energy2: [f32; 2 * NB_BANDS],
    /// The decode ring (`_decode_mem`, mono → one channel of `DECODE_BUFFER_SIZE + overlap`). Holds
    /// the synthesized SIG-domain time signal + the overlap tail across frames; the comb post-filter
    /// reaches back into it for pitch history.
    decode_mem: [f32; DECODE_MEM_LEN],
    /// De-emphasis 1-pole memory (`preemph_memD`), persists across frames.
    preemph_mem: f32,
    /// Range-coder state carried across frames (`st->rng`) — the anti-collapse / fold PRNG seed.
    rng: u32,
    /// Comb post-filter pitch period for the *current* frame (`postfilter_period`).
    postfilter_period: usize,
    /// Comb post-filter pitch period for the *previous* frame (`postfilter_period_old`).
    postfilter_period_old: usize,
    /// Comb post-filter gain, current frame (`postfilter_gain`).
    postfilter_gain: f32,
    /// Comb post-filter gain, previous frame (`postfilter_gain_old`).
    postfilter_gain_old: f32,
    /// Comb post-filter tapset, current frame (`postfilter_tapset`).
    postfilter_tapset: usize,
    /// Comb post-filter tapset, previous frame (`postfilter_tapset_old`).
    postfilter_tapset_old: usize,
    /// First coded band (`st->start`). 0 for CELT-only; 17 for Hybrid, where SILK carries everything
    /// below (RFC 6716 §4.3, `opus_decoder.c:546` `CELT_SET_START_BAND`).
    start_band: usize,
    /// One past the last coded band (`st->end`), set from the packet bandwidth — **not** always 21.
    /// See [`CeltDecoder::set_band_range`].
    end_band: usize,
}

impl CeltDecoder {
    /// Construct a fresh mono CELT decoder in the reset state (libopus `opus_custom_decoder_init` +
    /// `OPUS_RESET_STATE`, `celt_decoder.c:242,1794`): cleared ring/energy, `oldLogE/oldLogE2 = -28 dB`,
    /// `rng = 0`, post-filter params 0.
    pub fn new() -> Result<Self, CodecError> {
        // Base MDCT length 1920, shifts 0..=MAX_LM (=3) for the 48 kHz mode (`mdct.rs` docs).
        let mdct = MdctLookup::new(MDCT_BASE_LEN, MAX_LM)
            .map_err(|_| CodecError::Unsupported("celt: failed to build 48 kHz MDCT lookup"))?;
        Ok(Self {
            mdct,
            old_band_energy: [0.0; 2 * NB_BANDS],
            old_log_energy: [ENERGY_RESET_DB; 2 * NB_BANDS],
            old_log_energy2: [ENERGY_RESET_DB; 2 * NB_BANDS],
            decode_mem: [0.0; DECODE_MEM_LEN],
            preemph_mem: 0.0,
            rng: 0,
            postfilter_period: 0,
            postfilter_period_old: 0,
            postfilter_gain: 0.0,
            postfilter_gain_old: 0.0,
            postfilter_tapset: 0,
            postfilter_tapset_old: 0,
            start_band: 0,
            end_band: NB_BANDS,
        })
    }

    /// Set the coded band range (libopus `CELT_SET_START_BAND` / `CELT_SET_END_BAND`,
    /// `opus_decoder.c:523,546`).
    ///
    /// `end` is **derived from the packet bandwidth**, not fixed at 21 — a narrower bandwidth codes
    /// fewer bands, and decoding it as fullband desynchronises the range decoder
    /// (`opus_decoder.c:498-523`):
    ///
    /// | Bandwidth | `end` |
    /// |---|---|
    /// | Narrowband | 13 |
    /// | Medium / Wideband | 17 |
    /// | Super-wideband | 19 |
    /// | Fullband | 21 |
    ///
    /// `start` is 0 for CELT-only and 17 for Hybrid (SILK owns the bands below).
    pub fn set_band_range(&mut self, start: usize, end: usize) -> Result<(), CodecError> {
        if start > end || end > NB_BANDS {
            return Err(CodecError::Unsupported(
                "celt: band range must satisfy start <= end <= 21",
            ));
        }
        self.start_band = start;
        self.end_band = end;
        Ok(())
    }

    /// The range coder's final range after the last decoded frame (libopus `OPUS_GET_FINAL_RANGE`).
    ///
    /// `opus_demo` stores the *encoder's* final range alongside every packet it writes, and treats a
    /// decoder that ends a packet on a different value as a hard error ("Range coder state mismatch").
    /// It is therefore an exact, per-packet conformance oracle — far stricter than the `opus_compare`
    /// tolerance metric, and it localises a desync to the packet that caused it.
    #[must_use]
    pub fn final_range(&self) -> u32 {
        self.rng
    }

    /// The CELT `end` band for an Opus packet bandwidth (`opus_decoder.c:498-523`).
    #[must_use]
    pub fn end_band_for_bandwidth(bandwidth: Bandwidth) -> usize {
        match bandwidth {
            Bandwidth::Narrowband => 13,
            Bandwidth::Mediumband | Bandwidth::Wideband => 17,
            Bandwidth::SuperWideband => 19,
            Bandwidth::Fullband => NB_BANDS,
        }
    }

    /// Decode one mono CELT-only frame from `frame` into `pcm` as interleaved (mono → contiguous)
    /// 16-bit samples, returning the number of samples written. `frame_size` is the requested PCM
    /// sample count (which selects `LM`); it must be one of 120/240/480/960 (2.5/5/10/20 ms at
    /// 48 kHz). A faithful float port of `celt_decode_with_ec_dred` (`celt_decoder.c:1104`) for the
    /// valid-data, mono, CELT-only path — no PLC, no QEXT.
    pub fn decode(
        &mut self,
        frame: &[u8],
        pcm: &mut [i16],
        frame_size: usize,
    ) -> Result<usize, CodecError> {
        // ── Frame size → LM (celt_decoder.c:1260) ────────────────────────────────────────────────
        // shortMdctSize<<LM == frame_size for some LM in 0..=maxLM.
        let lm = (0..=MAX_LM)
            .find(|&candidate| (SHORT_MDCT_SIZE << candidate) == frame_size)
            .ok_or(CodecError::BadFrameSize {
                expected: SHORT_MDCT_SIZE << MAX_LM,
                got: frame_size,
            })?;

        // len<0 || len>1275 (celt_decoder.c:1268); a 0-or-1-byte frame would be the PLC path, which
        // is out of scope here — the caller routes a valid data packet to us.
        if frame.len() > 1275 {
            return Err(CodecError::Malformed("celt: frame longer than 1275 bytes"));
        }
        if frame.len() <= 1 {
            return Err(CodecError::Malformed(
                "celt: data packet must be >1 byte (PLC/DTX handled by the caller)",
            ));
        }

        let m = 1usize << lm; // M = 1<<LM (celt_decoder.c:1266)
        let n = m * SHORT_MDCT_SIZE; // N = M*shortMdctSize (celt_decoder.c:1271)
        let start = self.start_band; // st->start
        let end = self.end_band; // st->end, from the packet bandwidth (see `set_band_range`)
        let eff_end = end.min(NB_BANDS); // effEnd = IMIN(end, effEBands) (celt_decoder.c:1277)

        if pcm.len() < n {
            return Err(CodecError::OutputTooSmall {
                needed: n,
                have: pcm.len(),
            });
        }

        // ── ec_dec_init (celt_decoder.c:1305) ────────────────────────────────────────────────────
        let mut dec = RangeDecoder::new(frame);

        // C==1: fold the (duplicated) second channel's energy into the first (celt_decoder.c:1309).
        // On the mono path band E[NB_BANDS..] mirrors band E[..NB_BANDS] (kept in sync at frame end),
        // so this is the max of a value with itself; preserved for exactness.
        for i in 0..NB_BANDS {
            self.old_band_energy[i] =
                self.old_band_energy[i].max(self.old_band_energy[NB_BANDS + i]);
        }

        let total_bits_i = (frame.len() as i32) * 8; // total_bits = len*8 (celt_decoder.c:1315)

        // ── Silence flag (celt_decoder.c:1318) ───────────────────────────────────────────────────
        let tell = dec.tell();
        let silence = if tell >= total_bits_i {
            true
        } else if tell == 1 {
            dec.dec_bit_logp(15)
        } else {
            false
        };
        // libopus advances `nbits_total` to `len*8` on silence so every `tell+X<=total_bits` guard
        // below fails and no further symbols are read. `RangeDecoder` doesn't expose that knob, so on
        // a silent frame we still call the decode pipeline (which reads a few phantom symbols) — but
        // `silence` pins the energies and `denormalise_bands(silence=true)` zeroes the spectrum, so
        // the synthesized output is silent regardless. The only top-level guard we gate on `!silence`
        // is the post-filter (so a silent frame leaves the post-filter state untouched).

        // ── Post-filter params (start==0, celt_decoder.c:1334) ───────────────────────────────────
        let mut postfilter_gain = 0.0f32;
        let mut postfilter_pitch = 0usize;
        let mut postfilter_tapset = 0usize;
        let tell = dec.tell();
        // libopus nests the post-filter-present flag inside the bit-budget gate; `&&` short-circuit
        // keeps `dec_bit_logp` from being read unless the gate passes (identical bitstream order).
        if !silence && start == 0 && tell + 16 <= total_bits_i && dec.dec_bit_logp(1) {
            let octave = dec.dec_uint(6); // ec_dec_uint(dec, 6)
                                          // postfilter_pitch = (16<<octave) + ec_dec_bits(4+octave) - 1
            let period = dec.dec_bits(4 + octave);
            postfilter_pitch = ((16u32 << octave) + period - 1) as usize;
            let qg = dec.dec_bits(3); // ec_dec_bits(dec, 3)
            if dec.tell() + 2 <= total_bits_i {
                postfilter_tapset = dec.dec_icdf(&TAPSET_ICDF, 2);
            }
            // postfilter_gain = QCONST16(.09375f,15)*(qg+1) (float build: 0.09375*(qg+1)).
            postfilter_gain = 0.093_75 * (qg + 1) as f32;
        }

        // ── Transient flag (LM>0, celt_decoder.c:1349) ───────────────────────────────────────────
        let tell = dec.tell();
        let is_transient = if lm > 0 && tell + 3 <= total_bits_i {
            dec.dec_bit_logp(3)
        } else {
            false
        };
        let short_blocks = is_transient; // shortBlocks = isTransient ? M : 0; band decode takes a bool

        // ── Intra-energy flag (celt_decoder.c:1363) ──────────────────────────────────────────────
        let tell = dec.tell();
        let intra_ener = tell + 3 <= total_bits_i && dec.dec_bit_logp(3);

        // ── Coarse band energy (celt_decoder.c:1396) ─────────────────────────────────────────────
        unquant_coarse_energy(
            start,
            end,
            &mut self.old_band_energy,
            intra_ener,
            &mut dec,
            CHANNELS,
            lm,
        );

        // ── tf-resolution (celt_decoder.c:1400) ──────────────────────────────────────────────────
        let mut tf_res = [0i32; NB_BANDS];
        tf_decode(start, end, is_transient, &mut tf_res, lm, &mut dec);

        // ── Spread (celt_decoder.c:1403) ─────────────────────────────────────────────────────────
        let tell = dec.tell();
        let spread = if tell + 4 <= total_bits_i {
            dec.dec_icdf(&SPREAD_ICDF, 5) as u32
        } else {
            SPREAD_NORMAL
        };

        // ── Caps + dynalloc boost loop (celt_decoder.c:1407-1442) ────────────────────────────────
        let mut cap = [0i32; NB_BANDS];
        init_caps(&mut cap, lm, CHANNELS);

        let mut offsets = [0i32; NB_BANDS];
        let mut dynalloc_logp = 6i32;
        // total_bits <<= BITRES  → from here on the budget is in 1/8 bits (celt_decoder.c:1414).
        let mut total_bits_frac = total_bits_i << BITRES;
        let mut tell_frac = dec.tell_frac() as i32;
        for i in start..end {
            // width = C*(eBands[i+1]-eBands[i])<<LM
            let width = ((CHANNELS as i32) * i32::from(E_BANDS[i + 1] - E_BANDS[i])) << lm;
            // quanta = IMIN(width<<BITRES, IMAX(6<<BITRES, width))
            let quanta = (width << BITRES).min((6 << BITRES).max(width));
            let mut dynalloc_loop_logp = dynalloc_logp;
            let mut boost = 0i32;
            while tell_frac + (dynalloc_loop_logp << BITRES) < total_bits_frac && boost < cap[i] {
                let flag = dec.dec_bit_logp(dynalloc_loop_logp as u32);
                tell_frac = dec.tell_frac() as i32;
                if !flag {
                    break;
                }
                boost += quanta;
                total_bits_frac -= quanta;
                dynalloc_loop_logp = 1;
            }
            offsets[i] = boost;
            if boost > 0 {
                dynalloc_logp = 2.max(dynalloc_logp - 1);
            }
        }

        // ── Allocation trim (celt_decoder.c:1445) ────────────────────────────────────────────────
        let alloc_trim = if tell_frac + (6 << BITRES) <= total_bits_frac {
            dec.dec_icdf(&TRIM_ICDF, 7) as i32
        } else {
            5
        };

        // ── Bit budget for allocation + anti-collapse reservation (celt_decoder.c:1448) ──────────
        // bits = (len*8 << BITRES) - ec_tell_frac(dec) - 1   (1/8-bit units)
        let mut bits = (((frame.len() as i32) * 8) << BITRES) - dec.tell_frac() as i32 - 1;
        // anti_collapse_rsv = isTransient && LM>=2 && bits >= ((LM+2)<<BITRES) ? (1<<BITRES) : 0
        let anti_collapse_rsv = if is_transient && lm >= 2 && bits >= ((lm as i32 + 2) << BITRES) {
            1 << BITRES
        } else {
            0
        };
        bits -= anti_collapse_rsv;

        // ── Bit allocation (celt_decoder.c:1455) ─────────────────────────────────────────────────
        let mut intensity = 0usize;
        let mut dual_stereo = false;
        let mut pulses = [0i32; NB_BANDS];
        let mut fine_quant = [0i32; NB_BANDS];
        let mut fine_priority = [0i32; NB_BANDS];
        let mut balance = 0i32;
        let coded_bands = clt_compute_allocation(
            start,
            end,
            &offsets,
            &cap,
            alloc_trim,
            &mut intensity,
            &mut dual_stereo,
            bits,
            &mut balance,
            &mut pulses,
            &mut fine_quant,
            &mut fine_priority,
            CHANNELS,
            lm,
            // `prev` / `signal_bandwidth` drive the *encoder's* band-skip choice only; a decoder
            // reads the flags (`rate.c:346`), so these are unread here.
            0,
            0,
            &mut dec,
        );

        // ── Fine band energy (celt_decoder.c:1459) ───────────────────────────────────────────────
        unquant_fine_energy(
            start,
            end,
            &mut self.old_band_energy,
            &fine_quant,
            &mut dec,
            CHANNELS,
        );

        // ── Shift the decode ring left by N (celt_decoder.c:1487) ────────────────────────────────
        // OPUS_MOVE(decode_mem, decode_mem+N, decode_buffer_size-N+overlap): drop the oldest N
        // samples, sliding the rest down so the IMDCT overlap-add + the comb post-filter's pitch
        // history line up for this frame. The moved count is exactly `DECODE_MEM_LEN - N`, i.e. the
        // whole tail `[N..]` → `[0..]`.
        self.decode_mem.copy_within(n.., 0);

        // ── Band / PVQ decode (celt_decoder.c:1493) ──────────────────────────────────────────────
        // X is the C*N interleaved normalised MDCT coefficient buffer; mono → length N.
        let mut x = vec![0f32; n];
        let mut collapse_masks = [0u8; CHANNELS * NB_BANDS];
        // total_bits arg = len*(8<<BITRES) - anti_collapse_rsv  (1/8 bits).
        let band_total_bits = (frame.len() as i32) * (8 << BITRES) - anti_collapse_rsv;
        quant_all_bands(
            start,
            end,
            &mut x,
            &mut collapse_masks,
            &pulses,
            short_blocks,
            spread,
            intensity,
            &tf_res,
            band_total_bits,
            balance,
            lm as i32,
            coded_bands,
            &mut self.rng,
            true, // disable_inv = (channels == 1) → always true for mono (celt_decoder.c:261)
            &mut dec,
        );

        // ── Anti-collapse (celt_decoder.c:1520) ──────────────────────────────────────────────────
        let anti_collapse_on = if anti_collapse_rsv > 0 {
            dec.dec_bits(1) != 0
        } else {
            false
        };

        // ── Energy finalise (celt_decoder.c:1524) ────────────────────────────────────────────────
        // bits_left = len*8 - ec_tell(dec)
        unquant_energy_finalise(
            start,
            end,
            &mut self.old_band_energy,
            &fine_quant,
            &fine_priority,
            (frame.len() as i32) * 8 - dec.tell(),
            &mut dec,
            CHANNELS,
        );

        if anti_collapse_on {
            self.rng = anti_collapse(
                &mut x,
                &collapse_masks,
                lm,
                CHANNELS,
                n,
                start,
                end,
                &self.old_band_energy,
                &self.old_log_energy,
                &self.old_log_energy2,
                &pulses,
                self.rng,
            );
        }

        // On silence the energies are pinned to -28 dB (celt_decoder.c:1530).
        if silence {
            self.old_band_energy.fill(ENERGY_RESET_DB);
        }

        // ── Synthesis: denormalise + IMDCT + overlap-add into the decode ring (celt_decoder.c:1538)
        // `old_band_energy` is `Copy` (a fixed array), so pass it by value — this both reads the
        // final per-band energy and sidesteps borrowing `self` immutably across the `&mut self` call.
        let band_energy = self.old_band_energy;
        self.celt_synthesis(
            &x,
            &band_energy,
            start,
            eff_end,
            is_transient,
            lm,
            n,
            silence,
        );

        // ── Comb post-filter on out_syn (celt_decoder.c:1541-1564) ───────────────────────────────
        // out_syn[0] = decode_mem + DECODE_BUFFER_SIZE - N; comb_filter is in place on the ring,
        // reaching back into the (preserved) history before out_syn for the pitch taps.
        let out_syn = DECODE_BUFFER_SIZE - n;
        self.postfilter_period = self.postfilter_period.max(COMBFILTER_MINPERIOD);
        self.postfilter_period_old = self.postfilter_period_old.max(COMBFILTER_MINPERIOD);
        // First comb_filter: out_syn[0..shortMdctSize], old→current params.
        comb_filter(
            &mut self.decode_mem,
            out_syn,
            SHORT_MDCT_SIZE,
            self.postfilter_period_old,
            self.postfilter_period,
            self.postfilter_gain_old,
            self.postfilter_gain,
            self.postfilter_tapset_old,
            self.postfilter_tapset,
            &WINDOW120,
            OVERLAP,
        );
        if lm != 0 {
            // Second comb_filter: out_syn[shortMdctSize .. N], current→new (next frame) params.
            // `postfilter_pitch` is passed raw (unclamped) exactly as libopus does — `comb_filter`
            // clamps `t1` to COMBFILTER_MINPERIOD internally (postfilter.rs).
            comb_filter(
                &mut self.decode_mem,
                out_syn + SHORT_MDCT_SIZE,
                n - SHORT_MDCT_SIZE,
                self.postfilter_period,
                postfilter_pitch,
                self.postfilter_gain,
                postfilter_gain,
                self.postfilter_tapset,
                postfilter_tapset,
                &WINDOW120,
                OVERLAP,
            );
        }
        // Roll the post-filter params old<-current<-new (celt_decoder.c:1553).
        self.postfilter_period_old = self.postfilter_period;
        self.postfilter_gain_old = self.postfilter_gain;
        self.postfilter_tapset_old = self.postfilter_tapset;
        self.postfilter_period = postfilter_pitch;
        self.postfilter_gain = postfilter_gain;
        self.postfilter_tapset = postfilter_tapset;
        if lm != 0 {
            self.postfilter_period_old = self.postfilter_period;
            self.postfilter_gain_old = self.postfilter_gain;
            self.postfilter_tapset_old = self.postfilter_tapset;
        }

        // ── Energy history update (celt_decoder.c:1566-1596) ─────────────────────────────────────
        // C==1: mirror band energy into the (duplicated) second channel slots.
        for i in 0..NB_BANDS {
            self.old_band_energy[NB_BANDS + i] = self.old_band_energy[i];
        }
        if !is_transient {
            // oldLogE2 <- oldLogE <- oldBandE
            self.old_log_energy2 = self.old_log_energy;
            self.old_log_energy = self.old_band_energy;
        } else {
            // Transient: oldLogE = min(oldLogE, oldBandE).
            for (log_e, &band_e) in self
                .old_log_energy
                .iter_mut()
                .zip(self.old_band_energy.iter())
            {
                *log_e = log_e.min(band_e);
            }
        }
        // "In case start or end were to change" (celt_decoder.c:1344-1357): bands outside the coded
        // range are reset, for both channel slots, so a later frame that widens the range does not
        // predict from stale energy. Not a no-op once `end` tracks the packet bandwidth.
        for channel in 0..2 {
            let base = channel * NB_BANDS;
            for i in (0..start).chain(end..NB_BANDS) {
                self.old_band_energy[base + i] = 0.0;
                self.old_log_energy[base + i] = ENERGY_RESET_DB;
                self.old_log_energy2[base + i] = ENERGY_RESET_DB;
            }
        }
        // (`backgroundLogE` (celt_decoder.c:1341-1343) is consumed only by the PLC path, which this
        //  decoder does not implement yet; it must be added with concealment.)

        // Resync the cross-frame fold/anti-collapse PRNG seed to the range-coder register, so the
        // next frame's noise fold is seeded from the entropy state (celt_decoder.c:1597
        // `st->rng = dec->rng`). The in-frame fold/anti-collapse already consumed `self.rng` via
        // `quant_all_bands`/`anti_collapse`; this overwrite is what carries forward.
        self.rng = dec.rng();

        // ── De-emphasis → float PCM, then to i16 for the harness (celt_decoder.c:1602) ───────────
        // deemphasis(out_syn, pcm, N, C, 0, PREEMPH[0], &mut preemph_memD).
        // Caller-owned/stack scratch — the hot path must not heap-allocate per frame.
        let mut pcm_f = [0f32; MAX_FRAME_SAMPLES];
        deemphasis(
            &self.decode_mem[out_syn..out_syn + n],
            &mut pcm_f[..n],
            n,
            CHANNELS,
            0,
            PREEMPH[0],
            &mut self.preemph_mem,
        );
        for (dst, &sample) in pcm.iter_mut().zip(pcm_f.iter()).take(n) {
            *dst = float_to_i16(sample);
        }

        Ok(n)
    }

    /// CELT synthesis (libopus `celt_synthesis`, `celt_decoder.c:413`, mono float path): denormalise
    /// the band coefficients into the frequency buffer, then run the inverse MDCT of each short block
    /// straight into the decode ring at `out_syn`, where it overlap-adds with the preserved tail.
    #[allow(clippy::too_many_arguments)]
    fn celt_synthesis(
        &mut self,
        x: &[f32],
        old_band_energy: &[f32],
        start: usize,
        eff_end: usize,
        is_transient: bool,
        lm: usize,
        n: usize,
        silence: bool,
    ) {
        let m = 1usize << lm;
        // B / NB / shift (celt_decoder.c:438): transient → M short blocks of shortMdctSize at maxLM
        // shift; else one long block of N at (maxLM-LM).
        let (blocks, nb, shift) = if is_transient {
            (m, SHORT_MDCT_SIZE, MAX_LM)
        } else {
            (1usize, n, MAX_LM - lm)
        };

        // freq: the interleaved signal MDCTs (celt_decoder.c:432), length N.
        let mut freq = vec![0f32; n];
        denormalise_bands(x, &mut freq, old_band_energy, start, eff_end, m, 1, silence);

        // out_syn[0] = decode_mem + DECODE_BUFFER_SIZE - N (celt_decoder.c:1274).
        let out_syn = DECODE_BUFFER_SIZE - n;
        // For each short block b (celt_decoder.c:500): clt_mdct_backward reads `freq` with stride B
        // starting at offset b, and writes its block at `out_syn + NB*b`. Each backward MDCT writes
        // `overlap/2 + (mode->mdct.n>>shift)/2` samples — i.e. its `N/2` core PLUS the front overlap
        // half — so its destination must extend `overlap/2` past `out_syn + N`. We hand it the whole
        // remaining ring tail (`decode_mem[dst..]`, which has +overlap headroom by construction) and
        // it writes only the prefix it needs; the front `overlap/2` samples it touches are the
        // previous frame's preserved tail, giving the cross-frame overlap-add (mdct.c:371 mirror
        // fold reads the existing `out[..overlap/2]`).
        for b in 0..blocks {
            let dst = out_syn + nb * b;
            clt_mdct_backward(
                &self.mdct,
                &freq[b..],
                &mut self.decode_mem[dst..],
                &WINDOW120,
                OVERLAP,
                shift,
                blocks,
            );
        }
        // (libopus SATURATEs out_syn to SIG_SAT here; in the float build SATURATE is the identity
        //  outside the optional hardening guards, so we leave the samples untouched.)
    }
}

impl std::fmt::Debug for CeltDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeltDecoder")
            .field("rng", &self.rng)
            .field("postfilter_period", &self.postfilter_period)
            .field("postfilter_gain", &self.postfilter_gain)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;

    /// Construct a CELT decoder and decode a synthetic, in-range CELT bitstream. Full `opus_compare`
    /// validation needs SILK too (the RFC 6716 vectors are full-Opus packets), so this is a
    /// **structural smoke test**: the orchestration must drive every sub-component in order without
    /// panicking / indexing out of bounds, and must produce finite, in-range i16 PCM.
    #[test]
    fn decodes_synthetic_celt_frame_without_panic() {
        let mut decoder = CeltDecoder::new().expect("build mono CELT decoder");

        // A deterministic, plausible "random" payload. quant_* read it as range-coded symbols + raw
        // bits; any byte stream is a valid (if musically meaningless) bitstream — the decoder must
        // decode-or-stay-finite, never panic. >1 byte so we hit the data path (not PLC).
        let mut frame = vec![0u8; 80];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8;
        }
        // Bias toward the non-silence path (the silence bit is `val < rng>>15`) so we exercise the
        // full pipeline; either way the decode must stay finite and produce `frame_size` samples.
        frame[0] &= 0x7f;

        for &frame_size in &[120usize, 240, 480, 960] {
            let mut decoder = CeltDecoder::new().expect("build");
            let mut pcm = vec![0i16; frame_size];
            let written = decoder
                .decode(&frame, &mut pcm, frame_size)
                .expect("synthetic frame decodes");
            assert_eq!(written, frame_size, "frame_size={frame_size}");
            // i16 is inherently in range; the real assertion is "no panic + we got samples".
            assert_eq!(pcm.len(), frame_size);
        }

        // Decode a couple of consecutive frames to exercise the cross-frame ring / energy history.
        let mut pcm = vec![0i16; 960];
        for _ in 0..3 {
            decoder
                .decode(&frame, &mut pcm, 960)
                .expect("consecutive frames decode");
        }
    }

    /// A genuinely silent frame (tell==1 then the 1/15 silence bit set) must short-circuit to all-zero
    /// energies and produce (near-)silent PCM without touching the rest of the pipeline unsafely.
    #[test]
    fn silent_frame_decodes_to_low_energy() {
        // Encode: first symbol is the silence bit (logp=15, value=true). The range coder's first
        // tell() is 1, so the decoder takes the `tell==1` branch and reads this bit.
        let mut buf = vec![0u8; 64];
        {
            let mut enc = RangeEncoder::new(&mut buf);
            enc.enc_bit_logp(true, 15); // silence = 1
            enc.done();
            assert!(!enc.error());
        }

        let mut decoder = CeltDecoder::new().expect("build");
        let mut pcm = vec![0i16; 960];
        let written = decoder
            .decode(&buf, &mut pcm, 960)
            .expect("silent frame decodes");
        assert_eq!(written, 960);
        // De-emphasis of an all-zero SIG frame is ~silent; allow a small transient from the 1-pole
        // memory but assert it doesn't blow up.
        assert!(
            pcm.iter().all(|&s| s.abs() < 4000),
            "silent frame should be quiet"
        );
    }

    /// RFC 6716 §4.3 / `opus_decoder.c:498-523`: the CELT `end` band is derived from the packet
    /// bandwidth. Decoding a narrower bandwidth as fullband reads bands the encoder never coded and
    /// desynchronises the range decoder.
    #[test]
    fn end_band_follows_packet_bandwidth() {
        assert_eq!(
            CeltDecoder::end_band_for_bandwidth(Bandwidth::Narrowband),
            13
        );
        assert_eq!(
            CeltDecoder::end_band_for_bandwidth(Bandwidth::Mediumband),
            17
        );
        assert_eq!(CeltDecoder::end_band_for_bandwidth(Bandwidth::Wideband), 17);
        assert_eq!(
            CeltDecoder::end_band_for_bandwidth(Bandwidth::SuperWideband),
            19
        );
        assert_eq!(
            CeltDecoder::end_band_for_bandwidth(Bandwidth::Fullband),
            NB_BANDS
        );
    }

    #[test]
    fn defaults_to_the_fullband_celt_only_range() {
        let decoder = CeltDecoder::new().expect("build");
        assert_eq!(decoder.start_band, 0);
        assert_eq!(decoder.end_band, NB_BANDS);
    }

    #[test]
    fn set_band_range_accepts_every_real_configuration() {
        let mut decoder = CeltDecoder::new().expect("build");
        // Every CELT-only bandwidth, plus the Hybrid start band (SILK owns 0..17).
        for end in [13usize, 17, 19, NB_BANDS] {
            decoder.set_band_range(0, end).expect("celt-only range");
            assert_eq!(decoder.end_band, end);
        }
        decoder.set_band_range(17, NB_BANDS).expect("hybrid range");
        assert_eq!(decoder.start_band, 17);
        // Degenerate but legal: an empty range (start == end).
        decoder.set_band_range(5, 5).expect("empty range");
    }

    #[test]
    fn set_band_range_rejects_out_of_range() {
        let mut decoder = CeltDecoder::new().expect("build");
        assert!(decoder.set_band_range(0, NB_BANDS + 1).is_err());
        assert!(decoder.set_band_range(10, 4).is_err());
        // A rejected call must not have mutated the state.
        assert_eq!(decoder.start_band, 0);
        assert_eq!(decoder.end_band, NB_BANDS);
    }

    /// Bands outside the coded range must be reset after each frame (`celt_decoder.c:1344-1357`), in
    /// both channel slots, so widening the range later cannot predict from stale energy.
    #[test]
    fn decode_resets_energy_outside_the_coded_range() {
        let mut decoder = CeltDecoder::new().expect("build");
        // Seed every band with a value that is neither 0 nor the reset floor.
        decoder.old_band_energy = [7.0; 2 * NB_BANDS];
        decoder.old_log_energy = [7.0; 2 * NB_BANDS];
        decoder.old_log_energy2 = [7.0; 2 * NB_BANDS];
        decoder.set_band_range(0, 13).expect("narrowband range");

        let mut frame = vec![0u8; 60];
        for (i, b) in frame.iter_mut().enumerate() {
            *b = ((i as u32).wrapping_mul(2_654_435_761) >> 24) as u8;
        }
        frame[0] &= 0x7f; // bias away from the silence bit
        let mut pcm = vec![0i16; 960];
        decoder.decode(&frame, &mut pcm, 960).expect("decode");

        for channel in 0..2 {
            for band in 13..NB_BANDS {
                let i = channel * NB_BANDS + band;
                assert_eq!(
                    decoder.old_band_energy[i], 0.0,
                    "band {band} (channel {channel}) above end must be zeroed"
                );
                assert_eq!(decoder.old_log_energy[i], ENERGY_RESET_DB);
                assert_eq!(decoder.old_log_energy2[i], ENERGY_RESET_DB);
            }
        }
    }

    #[test]
    fn rejects_bad_frame_size() {
        let mut decoder = CeltDecoder::new().expect("build");
        let frame = vec![0x12u8; 40];
        let mut pcm = vec![0i16; 200];
        // 200 samples is not 120/240/480/960.
        let err = decoder.decode(&frame, &mut pcm, 200).unwrap_err();
        assert!(matches!(err, CodecError::BadFrameSize { .. }));
    }

    #[test]
    fn rejects_too_short_packet() {
        let mut decoder = CeltDecoder::new().expect("build");
        let mut pcm = vec![0i16; 960];
        // <=1 byte is the PLC/DTX path, which the caller owns — we reject it here.
        assert!(decoder.decode(&[0x00], &mut pcm, 960).is_err());
        assert!(decoder.decode(&[], &mut pcm, 960).is_err());
    }

    #[test]
    fn rejects_undersized_output() {
        let mut decoder = CeltDecoder::new().expect("build");
        let frame = vec![0x34u8; 40];
        let mut pcm = vec![0i16; 100]; // < 960
        let err = decoder.decode(&frame, &mut pcm, 960).unwrap_err();
        assert!(matches!(err, CodecError::OutputTooSmall { .. }));
    }
}
