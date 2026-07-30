//! Opus range coder — the entropy coder shared by SILK and CELT (RFC 6716 §4.1).
//!
//! A range coder (a carry-propagating variant of arithmetic coding). It operates over **two
//! independent bit-streams packed into one byte buffer growing toward each other**: the range-coded
//! symbols are written/read **forward** from the front (`offs`), while *raw bits*
//! ([`RangeEncoder::enc_bits`] / [`RangeDecoder::dec_bits`]) are written/read **backward** from the
//! end (`end_offs`) — RFC 6716 calls these "the back of the buffer". Overflow is when the two halves
//! meet (`offs + end_offs >= storage`).
//!
//! This is **Phase 1** of the pure-Rust Opus port (decoder-first, phased): the entropy foundation
//! both the CELT and SILK layers sit on. It is a faithful port of libopus `entcode`/`entdec`/`entenc`
//! and is validated by encode↔decode round-trip — the coder is a lossless, exactly-invertible entropy
//! coder, so the encoder is its own decoder oracle (no external vectors needed at this layer).
//!
//! Arithmetic matches the C unsigned/`int` semantics exactly (`wrapping_*` where C relies on unsigned
//! overflow — notably the encoder carry). Field names follow libopus so the steps map onto §4.1.

// ── Constants (libopus mfrngcod.h / entcode.h) ─────────────────────────────────────────────────
const EC_SYM_BITS: u32 = 8;
const EC_CODE_BITS: u32 = 32;
const EC_SYM_MAX: u32 = 255;
const EC_CODE_SHIFT: u32 = EC_CODE_BITS - EC_SYM_BITS - 1; // 23
const EC_CODE_TOP: u32 = 1u32 << (EC_CODE_BITS - 1); // 2^31
const EC_CODE_BOT: u32 = EC_CODE_TOP >> EC_SYM_BITS; // 2^23
const EC_CODE_EXTRA: u32 = (EC_CODE_BITS - 2) % EC_SYM_BITS + 1; // 7
const EC_UINT_BITS: u32 = 8;
const EC_WINDOW_SIZE: u32 = 32;
const BITRES: u32 = 3;

/// `1 + floor(log2(v))` for `v > 0`, and `0` for `v == 0` (libopus `ec_ilog` / `EC_ILOG`).
#[inline]
fn ec_ilog(v: u32) -> i32 {
    (EC_CODE_BITS - v.leading_zeros()) as i32
}

/// Bits used so far, rounded up (libopus `ec_tell`). Shared by encoder and decoder.
#[inline]
fn ec_tell(nbits_total: i32, rng: u32) -> i32 {
    nbits_total - ec_ilog(rng)
}

/// Bits used so far in 1/8-bit units (libopus `ec_tell_frac`). Must be identical between encoder and
/// decoder — CELT's bit-budget decisions depend on it.
fn ec_tell_frac(nbits_total: i32, rng: u32) -> u32 {
    const CORRECTION: [u32; 8] = [35733, 38967, 42495, 46340, 50535, 55109, 60097, 65535];
    let nbits = (nbits_total as u32) << BITRES;
    let l = ec_ilog(rng) as u32;
    let r = rng >> (l - 16);
    let mut b = (r >> 12) - 8;
    b += u32::from(r > CORRECTION[b as usize]);
    let l = (l << 3) + b;
    nbits - l
}

// ── Decoder ────────────────────────────────────────────────────────────────────────────────────

/// Opus range *decoder* over a borrowed packet buffer (libopus `ec_dec`).
pub struct RangeDecoder<'a> {
    buf: &'a [u8],
    storage: u32,
    offs: u32,
    end_offs: u32,
    end_window: u32,
    nend_bits: i32,
    nbits_total: i32,
    rng: u32,
    val: u32,
    /// Decoder: saved normalization factor `rng/ft` from the last [`Self::decode`].
    ext: u32,
    /// Last range-coder byte read (0..=255).
    rem: i32,
    error: i32,
}

impl<'a> RangeDecoder<'a> {
    /// Initialize a decoder over `buf` (libopus `ec_dec_init`).
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        let storage = buf.len() as u32;
        let mut dec = Self {
            buf,
            storage,
            offs: 0,
            end_offs: 0,
            end_window: 0,
            nend_bits: 0,
            nbits_total: (EC_CODE_BITS + 1
                - ((EC_CODE_BITS - EC_CODE_EXTRA) / EC_SYM_BITS) * EC_SYM_BITS)
                as i32,
            rng: 1u32 << EC_CODE_EXTRA,
            val: 0,
            ext: 0,
            rem: 0,
            error: 0,
        };
        dec.rem = dec.read_byte();
        dec.val = dec.rng - 1 - (dec.rem >> (EC_SYM_BITS - EC_CODE_EXTRA)) as u32;
        dec.normalize();
        dec
    }

    /// Non-zero if a malformed stream was detected (e.g. [`Self::dec_uint`] out of range).
    #[must_use]
    pub fn error(&self) -> bool {
        self.error != 0
    }

    /// Bits read so far, rounded up.
    #[must_use]
    pub fn tell(&self) -> i32 {
        ec_tell(self.nbits_total, self.rng)
    }

    /// The current range-coder normalization register `rng` (libopus `dec->rng`). CELT resyncs its
    /// cross-frame fold/anti-collapse PRNG seed to this at frame end (`st->rng = dec->rng`,
    /// `celt_decoder.c:1597`), so the next frame's noise fold is seeded from the entropy state.
    #[must_use]
    pub fn rng(&self) -> u32 {
        self.rng
    }

    /// Bits read so far in 1/8-bit units.
    #[must_use]
    pub fn tell_frac(&self) -> u32 {
        ec_tell_frac(self.nbits_total, self.rng)
    }

    /// Total buffer size in bits (libopus `dec->storage*8`) — the absolute bit budget the CELT
    /// coarse-energy decode compares `tell()` against.
    #[must_use]
    pub fn storage_bits(&self) -> u32 {
        self.storage * 8
    }

    #[inline]
    fn read_byte(&mut self) -> i32 {
        if self.offs < self.storage {
            let b = self.buf[self.offs as usize];
            self.offs += 1;
            i32::from(b)
        } else {
            0
        }
    }

    #[inline]
    fn read_byte_from_end(&mut self) -> i32 {
        if self.end_offs < self.storage {
            self.end_offs += 1;
            i32::from(self.buf[(self.storage - self.end_offs) as usize])
        } else {
            0
        }
    }

    fn normalize(&mut self) {
        while self.rng <= EC_CODE_BOT {
            self.nbits_total += EC_SYM_BITS as i32;
            self.rng <<= EC_SYM_BITS;
            let sym = self.rem;
            self.rem = self.read_byte();
            let sym = ((sym << EC_SYM_BITS) | self.rem) >> (EC_SYM_BITS - EC_CODE_EXTRA);
            self.val = (self.val << EC_SYM_BITS).wrapping_add(EC_SYM_MAX & !(sym as u32))
                & (EC_CODE_TOP - 1);
        }
    }

    /// Decode a cumulative frequency in `[0, ft)` for a symbol with total frequency `ft`
    /// (libopus `ec_decode`). Must be followed by [`Self::dec_update`].
    pub fn decode(&mut self, ft: u32) -> u32 {
        self.ext = self.rng / ft;
        let s = self.val / self.ext;
        ft - (s + 1).min(ft)
    }

    /// As [`Self::decode`] with `ft = 1 << bits` (libopus `ec_decode_bin`).
    pub fn decode_bin(&mut self, bits: u32) -> u32 {
        self.ext = self.rng >> bits;
        let s = self.val / self.ext;
        (1u32 << bits) - (s + 1).min(1u32 << bits)
    }

    /// Advance the decoder past a symbol occupying `[fl, fh)` of `ft` (libopus `ec_dec_update`).
    pub fn dec_update(&mut self, fl: u32, fh: u32, ft: u32) {
        let s = self.ext.wrapping_mul(ft - fh);
        self.val = self.val.wrapping_sub(s);
        self.rng = if fl > 0 {
            self.ext.wrapping_mul(fh - fl)
        } else {
            self.rng - s
        };
        self.normalize();
    }

    /// Decode a single bit with probability `1/(1<<logp)` of being one (libopus `ec_dec_bit_logp`).
    pub fn dec_bit_logp(&mut self, logp: u32) -> bool {
        let r = self.rng;
        let d = self.val;
        let s = r >> logp;
        let ret = d < s;
        if !ret {
            self.val = d - s;
        }
        self.rng = if ret { s } else { r - s };
        self.normalize();
        ret
    }

    /// Decode a symbol with the given inverse-CDF table (non-increasing, last entry 0;
    /// `ft = 1 << ftb`) — libopus `ec_dec_icdf`.
    pub fn dec_icdf(&mut self, icdf: &[u8], ftb: u32) -> usize {
        let mut s = self.rng;
        let d = self.val;
        let r = s >> ftb;
        let mut ret: usize = 0;
        let mut t;
        loop {
            t = s;
            s = r.wrapping_mul(u32::from(icdf[ret]));
            if d >= s {
                break;
            }
            ret += 1;
        }
        self.val = d.wrapping_sub(s);
        self.rng = t.wrapping_sub(s);
        self.normalize();
        ret
    }

    /// `dec_icdf` with a 16-bit table (`ft = 1 << ftb`) — libopus `ec_dec_icdf16` (used by SILK).
    pub fn dec_icdf16(&mut self, icdf: &[u16], ftb: u32) -> usize {
        let mut s = self.rng;
        let d = self.val;
        let r = s >> ftb;
        let mut ret: usize = 0;
        let mut t;
        loop {
            t = s;
            s = r.wrapping_mul(u32::from(icdf[ret]));
            if d >= s {
                break;
            }
            ret += 1;
        }
        self.val = d.wrapping_sub(s);
        self.rng = t.wrapping_sub(s);
        self.normalize();
        ret
    }

    /// Decode a uniformly-distributed integer in `[0, ft)` (libopus `ec_dec_uint`). `ft` must be ≥ 2.
    pub fn dec_uint(&mut self, ft: u32) -> u32 {
        debug_assert!(ft > 1);
        let ftn = ft - 1;
        let ftb = ec_ilog(ftn) as u32;
        if ftb > EC_UINT_BITS {
            let ftb = ftb - EC_UINT_BITS;
            let ftt = (ftn >> ftb) + 1;
            let s = self.decode(ftt);
            self.dec_update(s, s + 1, ftt);
            let t = (s << ftb) | self.dec_bits(ftb);
            if t <= ftn {
                t
            } else {
                self.error = 1;
                ftn
            }
        } else {
            let ftt = ftn + 1;
            let s = self.decode(ftt);
            self.dec_update(s, s + 1, ftt);
            s
        }
    }

    /// Read `bits` raw bits from the back of the buffer (libopus `ec_dec_bits`).
    pub fn dec_bits(&mut self, bits: u32) -> u32 {
        let mut window = self.end_window;
        let mut available = self.nend_bits;
        if (available as u32) < bits {
            loop {
                window |= (self.read_byte_from_end() as u32) << available;
                available += EC_SYM_BITS as i32;
                if available > (EC_WINDOW_SIZE - EC_SYM_BITS) as i32 {
                    break;
                }
            }
        }
        let ret = window & ((1u32 << bits) - 1);
        window >>= bits;
        available -= bits as i32;
        self.end_window = window;
        self.nend_bits = available;
        self.nbits_total += bits as i32;
        ret
    }
}

// ── Encoder ──────────────────────────────────────────────────────────────────────────────────────

/// Opus range *encoder* over a borrowed output buffer (libopus `ec_enc`). Implemented alongside the
/// decoder so the entropy layer is validated by round-trip, and as the foundation for the eventual
/// Opus encoder.
pub struct RangeEncoder<'a> {
    buf: &'a mut [u8],
    storage: u32,
    offs: u32,
    end_offs: u32,
    end_window: u32,
    nend_bits: i32,
    nbits_total: i32,
    rng: u32,
    val: u32,
    /// Encoder: count of outstanding carry-propagating (0xFF) symbols.
    ext: u32,
    /// Buffered output byte awaiting carry resolution (`-1` until the first write).
    rem: i32,
    error: i32,
}

/// A rollback point for [`RangeEncoder`] — every scalar field of libopus' `ec_enc`, so a trial
/// encode can be undone (`quant_bands.c:296,333`). The output *bytes* are deliberately excluded:
/// they are large and the caller only ever needs the range it actually touched.
#[derive(Clone, Copy, Debug)]
pub struct RangeEncoderState {
    storage: u32,
    offs: u32,
    end_offs: u32,
    end_window: u32,
    nend_bits: i32,
    nbits_total: i32,
    rng: u32,
    val: u32,
    ext: u32,
    rem: i32,
    error: i32,
}

impl<'a> RangeEncoder<'a> {
    /// Initialize an encoder writing into `buf` (libopus `ec_enc_init`).
    #[must_use]
    pub fn new(buf: &'a mut [u8]) -> Self {
        let storage = buf.len() as u32;
        Self {
            buf,
            storage,
            offs: 0,
            end_offs: 0,
            end_window: 0,
            nend_bits: 0,
            nbits_total: (EC_CODE_BITS + 1) as i32,
            rng: EC_CODE_TOP,
            val: 0,
            ext: 0,
            rem: -1,
            error: 0,
        }
    }

    /// Non-zero if the buffer overflowed (or a patch failed).
    #[must_use]
    pub fn error(&self) -> bool {
        self.error != 0
    }

    /// Bits written so far, rounded up.
    #[must_use]
    pub fn tell(&self) -> i32 {
        ec_tell(self.nbits_total, self.rng)
    }

    /// Bits written so far in 1/8-bit units.
    #[must_use]
    pub fn tell_frac(&self) -> u32 {
        ec_tell_frac(self.nbits_total, self.rng)
    }

    /// The current range value (libopus `ec_ctx.rng` / `OPUS_GET_FINAL_RANGE` after
    /// [`Self::done`]) — the exact per-packet conformance oracle a decoder must reproduce.
    #[must_use]
    pub fn rng(&self) -> u32 {
        self.rng
    }

    /// The output buffer's capacity in bits (libopus `enc->storage*8`, the budget every
    /// `tell + X <= budget` gate in the CELT encoder compares against).
    #[must_use]
    pub fn storage_bits(&self) -> u32 {
        self.storage * 8
    }

    /// Bytes the range coder has written from the front of the buffer (libopus `ec_range_bytes`).
    /// The two-pass coarse-energy trial uses it to bound the byte range it must save and restore.
    #[must_use]
    pub fn range_bytes(&self) -> u32 {
        self.offs
    }

    /// Read-only view of the output buffer (libopus `ec_get_buffer`).
    #[must_use]
    pub fn buffer(&self) -> &[u8] {
        self.buf
    }

    /// Mutable view of the output buffer, for restoring a trial encode's bytes
    /// (`quant_bands.c:342`). Prefer the `enc_*` methods for everything else.
    pub fn buffer_mut(&mut self) -> &mut [u8] {
        self.buf
    }

    /// Account the whole packet as already written (libopus `celt_encoder.c:1673`,
    /// `enc->nbits_total += tell - ec_tell(enc)` on a silent frame): every later
    /// `tell + X <= total_bits` budget gate then fails, so no further symbols get coded and the
    /// remaining bytes stay the zeros the initialiser left.
    pub fn declare_bits_used(&mut self, total_bits: i32) {
        self.nbits_total += total_bits - self.tell();
    }

    /// Snapshot the scalar coder state so a trial encode can be rolled back
    /// (libopus copies the whole struct: `quant_bands.c:296` `enc_start_state = *enc`).
    #[must_use]
    pub fn save_state(&self) -> RangeEncoderState {
        RangeEncoderState {
            storage: self.storage,
            offs: self.offs,
            end_offs: self.end_offs,
            end_window: self.end_window,
            nend_bits: self.nend_bits,
            nbits_total: self.nbits_total,
            rng: self.rng,
            val: self.val,
            ext: self.ext,
            rem: self.rem,
            error: self.error,
        }
    }

    /// Restore a [`Self::save_state`] snapshot. The buffer bytes are **not** restored — the caller
    /// saves and replays the affected byte range itself, exactly as `quant_coarse_energy` does.
    pub fn restore_state(&mut self, state: &RangeEncoderState) {
        self.storage = state.storage;
        self.offs = state.offs;
        self.end_offs = state.end_offs;
        self.end_window = state.end_window;
        self.nend_bits = state.nend_bits;
        self.nbits_total = state.nbits_total;
        self.rng = state.rng;
        self.val = state.val;
        self.ext = state.ext;
        self.rem = state.rem;
        self.error = state.error;
    }

    #[inline]
    fn write_byte(&mut self, value: u32) -> i32 {
        if self.offs + self.end_offs >= self.storage {
            return -1;
        }
        self.buf[self.offs as usize] = value as u8;
        self.offs += 1;
        0
    }

    #[inline]
    fn write_byte_at_end(&mut self, value: u32) -> i32 {
        if self.offs + self.end_offs >= self.storage {
            return -1;
        }
        self.end_offs += 1;
        self.buf[(self.storage - self.end_offs) as usize] = value as u8;
        0
    }

    /// Carry-propagation core (libopus `ec_enc_carry_out`) — the subtlest piece; ported line-for-line.
    fn carry_out(&mut self, c: i32) {
        if c as u32 != EC_SYM_MAX {
            let carry = c >> EC_SYM_BITS;
            if self.rem >= 0 {
                self.error |= self.write_byte((self.rem + carry) as u32);
            }
            if self.ext > 0 {
                let sym = (EC_SYM_MAX.wrapping_add(carry as u32)) & EC_SYM_MAX;
                loop {
                    self.error |= self.write_byte(sym);
                    self.ext -= 1;
                    if self.ext == 0 {
                        break;
                    }
                }
            }
            self.rem = c & EC_SYM_MAX as i32;
        } else {
            self.ext += 1;
        }
    }

    fn normalize(&mut self) {
        while self.rng <= EC_CODE_BOT {
            self.carry_out((self.val >> EC_CODE_SHIFT) as i32);
            self.val = (self.val << EC_SYM_BITS) & (EC_CODE_TOP - 1);
            self.rng <<= EC_SYM_BITS;
            self.nbits_total += EC_SYM_BITS as i32;
        }
    }

    /// Encode a symbol occupying `[fl, fh)` of total frequency `ft` (libopus `ec_encode`).
    pub fn encode(&mut self, fl: u32, fh: u32, ft: u32) {
        let r = self.rng / ft;
        if fl > 0 {
            self.val = self
                .val
                .wrapping_add(self.rng.wrapping_sub(r.wrapping_mul(ft - fl)));
            self.rng = r.wrapping_mul(fh - fl);
        } else {
            self.rng -= r.wrapping_mul(ft - fh);
        }
        self.normalize();
    }

    /// As [`Self::encode`] with `ft = 1 << bits` (libopus `ec_encode_bin`).
    pub fn encode_bin(&mut self, fl: u32, fh: u32, bits: u32) {
        let r = self.rng >> bits;
        if fl > 0 {
            self.val = self
                .val
                .wrapping_add(self.rng.wrapping_sub(r.wrapping_mul((1u32 << bits) - fl)));
            self.rng = r.wrapping_mul(fh - fl);
        } else {
            self.rng -= r.wrapping_mul((1u32 << bits) - fh);
        }
        self.normalize();
    }

    /// Encode a single bit with probability `1/(1<<logp)` of being one (libopus `ec_enc_bit_logp`).
    pub fn enc_bit_logp(&mut self, val: bool, logp: u32) {
        let r = self.rng;
        let l = self.val;
        let s = r >> logp;
        let r = r - s;
        if val {
            self.val = l.wrapping_add(r);
        }
        self.rng = if val { s } else { r };
        self.normalize();
    }

    /// Encode symbol `s` via its inverse-CDF table (libopus `ec_enc_icdf`).
    pub fn enc_icdf(&mut self, s: usize, icdf: &[u8], ftb: u32) {
        let r = self.rng >> ftb;
        if s > 0 {
            self.val = self.val.wrapping_add(
                self.rng
                    .wrapping_sub(r.wrapping_mul(u32::from(icdf[s - 1]))),
            );
            self.rng = r.wrapping_mul(u32::from(icdf[s - 1]) - u32::from(icdf[s]));
        } else {
            self.rng -= r.wrapping_mul(u32::from(icdf[s]));
        }
        self.normalize();
    }

    /// `enc_icdf` with a 16-bit table (libopus `ec_enc_icdf16`).
    pub fn enc_icdf16(&mut self, s: usize, icdf: &[u16], ftb: u32) {
        let r = self.rng >> ftb;
        if s > 0 {
            self.val = self.val.wrapping_add(
                self.rng
                    .wrapping_sub(r.wrapping_mul(u32::from(icdf[s - 1]))),
            );
            self.rng = r.wrapping_mul(u32::from(icdf[s - 1]) - u32::from(icdf[s]));
        } else {
            self.rng -= r.wrapping_mul(u32::from(icdf[s]));
        }
        self.normalize();
    }

    /// Encode a uniformly-distributed integer `fl` in `[0, ft)` (libopus `ec_enc_uint`). `ft` ≥ 2.
    pub fn enc_uint(&mut self, fl: u32, ft: u32) {
        debug_assert!(ft > 1);
        let ftn = ft - 1;
        let ftb = ec_ilog(ftn) as u32;
        if ftb > EC_UINT_BITS {
            let ftb = ftb - EC_UINT_BITS;
            let ftt = (ftn >> ftb) + 1;
            let fl_hi = fl >> ftb;
            self.encode(fl_hi, fl_hi + 1, ftt);
            self.enc_bits(fl & ((1u32 << ftb) - 1), ftb);
        } else {
            self.encode(fl, fl + 1, ftn + 1);
        }
    }

    /// Write `bits` raw bits to the back of the buffer (libopus `ec_enc_bits`).
    pub fn enc_bits(&mut self, fl: u32, bits: u32) {
        let mut window = self.end_window;
        let mut used = self.nend_bits;
        debug_assert!(bits > 0);
        if used as u32 + bits > EC_WINDOW_SIZE {
            loop {
                self.error |= self.write_byte_at_end(window & EC_SYM_MAX);
                window >>= EC_SYM_BITS;
                used -= EC_SYM_BITS as i32;
                if used < EC_SYM_BITS as i32 {
                    break;
                }
            }
        }
        window |= fl << used;
        used += bits as i32;
        self.end_window = window;
        self.nend_bits = used;
        self.nbits_total += bits as i32;
    }

    /// Overwrite the top `nbits` (≤ 8) of the very first encoded byte (libopus
    /// `ec_enc_patch_initial_bits`). Sets `error` if too few bits have been encoded.
    pub fn patch_initial_bits(&mut self, val: u32, nbits: u32) {
        debug_assert!(nbits <= EC_SYM_BITS);
        let shift = (EC_SYM_BITS - nbits) as i32;
        let mask = (((1u32 << nbits) - 1) << shift) as u8;
        if self.offs > 0 {
            self.buf[0] = (self.buf[0] & !mask) | ((val << shift) as u8);
        } else if self.rem >= 0 {
            self.rem = (self.rem & !(mask as i32)) | ((val << shift) as i32);
        } else if self.rng <= EC_CODE_TOP >> nbits {
            self.val = (self.val & !((mask as u32) << EC_CODE_SHIFT))
                | (val << (EC_CODE_SHIFT + shift as u32));
        } else {
            self.error = -1;
        }
    }

    /// Shrink the buffer to `size`, relocating the raw-bit bytes at the end (libopus `ec_enc_shrink`).
    pub fn shrink(&mut self, size: u32) {
        debug_assert!(self.offs + self.end_offs <= size);
        let src = (self.storage - self.end_offs) as usize;
        let dst = (size - self.end_offs) as usize;
        self.buf.copy_within(src..src + self.end_offs as usize, dst);
        self.storage = size;
    }

    /// Flush the encoder and finalize the buffer (libopus `ec_enc_done`). Returns the number of
    /// front (range-coder) bytes written; the full buffer (front + back raw bits) is the packet.
    pub fn done(&mut self) -> u32 {
        let mut l = (EC_CODE_BITS as i32) - ec_ilog(self.rng);
        let mut msk = (EC_CODE_TOP - 1) >> l;
        let mut end = self.val.wrapping_add(msk) & !msk;
        if (end | msk) >= self.val.wrapping_add(self.rng) {
            l += 1;
            msk >>= 1;
            end = self.val.wrapping_add(msk) & !msk;
        }
        while l > 0 {
            self.carry_out((end >> EC_CODE_SHIFT) as i32);
            end = (end << EC_SYM_BITS) & (EC_CODE_TOP - 1);
            l -= EC_SYM_BITS as i32;
        }
        if self.rem >= 0 || self.ext > 0 {
            self.carry_out(0);
        }
        let mut window = self.end_window;
        let mut used = self.nend_bits;
        while used >= EC_SYM_BITS as i32 {
            self.error |= self.write_byte_at_end(window & EC_SYM_MAX);
            window >>= EC_SYM_BITS;
            used -= EC_SYM_BITS as i32;
        }
        if self.error == 0 {
            let clear_from = self.offs as usize;
            let clear_to = (self.storage - self.end_offs) as usize;
            for b in &mut self.buf[clear_from..clear_to] {
                *b = 0;
            }
            if used > 0 {
                if self.end_offs >= self.storage {
                    self.error = -1;
                } else {
                    l = -l;
                    if self.offs + self.end_offs >= self.storage && l < used {
                        window &= (1u32 << l) - 1;
                        self.error = -1;
                    }
                    let idx = (self.storage - self.end_offs - 1) as usize;
                    self.buf[idx] |= window as u8;
                }
            }
        }
        self.offs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ilog_matches_definition() {
        assert_eq!(ec_ilog(0), 0);
        assert_eq!(ec_ilog(1), 1);
        assert_eq!(ec_ilog(2), 2);
        assert_eq!(ec_ilog(255), 8);
        assert_eq!(ec_ilog(256), 9);
        assert_eq!(ec_ilog(0x8000_0000), 32);
    }

    /// Port of libopus `test_unit_entropy.c`: encode a stream of `ec_enc_uint` + raw bits, then
    /// decode it and require every value back exactly, plus encoder/decoder `tell_frac` parity.
    #[test]
    fn roundtrips_uint_and_raw_bits_with_tell_parity() {
        let mut buf = vec![0u8; 200_000];
        // (is_raw, value, param, enc_tell_frac_after)
        let mut log: Vec<(bool, u32, u32, u32)> = Vec::new();
        {
            let mut enc = RangeEncoder::new(&mut buf);
            for ft in 2u32..1024 {
                let v = (ft.wrapping_mul(2_654_435_761) >> 8) % ft;
                enc.enc_uint(v, ft);
                log.push((false, v, ft, enc.tell_frac()));
            }
            for bits in 1u32..16 {
                let v = (bits.wrapping_mul(40_503)) & ((1u32 << bits) - 1);
                enc.enc_bits(v, bits);
                log.push((true, v, bits, enc.tell_frac()));
            }
            enc.done();
            assert!(!enc.error(), "encoder must not overflow a 200k buffer");
        }
        let mut dec = RangeDecoder::new(&buf);
        for &(is_raw, v, p, enc_tell) in &log {
            let got = if is_raw {
                dec.dec_bits(p)
            } else {
                dec.dec_uint(p)
            };
            assert_eq!(got, v, "roundtrip mismatch (raw={is_raw}, param={p})");
            assert_eq!(
                dec.tell_frac(),
                enc_tell,
                "tell_frac parity (raw={is_raw}, param={p})"
            );
        }
        assert!(!dec.error());
    }

    /// The four symbol-coding methods must interoperate bit-for-bit (encode one way, decode the
    /// matching way) — libopus's cross-method compatibility check.
    #[test]
    fn icdf_and_logp_roundtrip() {
        // A small non-increasing inverse-CDF (ftb=4 → ft=16): symbols of freq {6,5,4,1}.
        let icdf: [u8; 4] = [10, 5, 1, 0];
        let symbols = [0usize, 3, 1, 2, 2, 0, 1, 3, 0, 2];
        let bits = [true, false, true, true, false, false, true, false];
        let mut buf = vec![0u8; 1024];
        {
            let mut enc = RangeEncoder::new(&mut buf);
            for &s in &symbols {
                enc.enc_icdf(s, &icdf, 4);
            }
            for &b in &bits {
                enc.enc_bit_logp(b, 3);
            }
            enc.done();
            assert!(!enc.error());
        }
        let mut dec = RangeDecoder::new(&buf);
        for &s in &symbols {
            assert_eq!(dec.dec_icdf(&icdf, 4), s);
        }
        for &b in &bits {
            assert_eq!(dec.dec_bit_logp(3), b);
        }
    }

    #[test]
    fn encode_decode_via_decode_update_roundtrip() {
        // Raw ec_encode / ec_decode + ec_dec_update over a small alphabet.
        // Symbol table: cumulative freqs over ft=20, three symbols [0,8),[8,15),[15,20).
        let bounds = [(0u32, 8u32), (8, 15), (15, 20)];
        let ft = 20;
        let seq = [0usize, 1, 2, 1, 0, 2, 2, 1, 0];
        let mut buf = vec![0u8; 1024];
        {
            let mut enc = RangeEncoder::new(&mut buf);
            for &i in &seq {
                let (fl, fh) = bounds[i];
                enc.encode(fl, fh, ft);
            }
            enc.done();
        }
        let mut dec = RangeDecoder::new(&buf);
        for &i in &seq {
            let fs = dec.decode(ft);
            // Find which symbol fs falls into, then update.
            let sym = bounds
                .iter()
                .position(|&(fl, fh)| fs >= fl && fs < fh)
                .expect("symbol");
            assert_eq!(sym, i);
            let (fl, fh) = bounds[sym];
            dec.dec_update(fl, fh, ft);
        }
    }

    #[test]
    fn patch_initial_bits_sets_known_byte() {
        // libopus test: after a couple of symbols, patch the top 2 bits to 0b11 → buf[0] high bits set.
        let mut buf = vec![0u8; 64];
        let mut enc = RangeEncoder::new(&mut buf);
        enc.enc_bit_logp(false, 1);
        enc.enc_bit_logp(true, 1);
        enc.patch_initial_bits(3, 2);
        assert!(!enc.error());
        enc.done();
        assert_eq!(buf[0] >> 6, 0b11, "top 2 bits patched to 3");
    }

    #[test]
    fn decoder_tolerates_arbitrary_bytes_without_panicking() {
        // A hostile/garbage buffer must decode-or-flag-error, never panic / index out of bounds.
        let buf: Vec<u8> = (0..256u32)
            .map(|k| (k.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let mut dec = RangeDecoder::new(&buf);
        for _ in 0..200 {
            let _ = dec.dec_uint(64);
            let _ = dec.dec_bits(5);
            let _ = dec.dec_icdf(&[12, 4, 0], 4);
        }
        // No assertion on values — the contract is "no panic / no OOB"; reading past the buffer
        // yields phantom zeros by design.
    }
}
