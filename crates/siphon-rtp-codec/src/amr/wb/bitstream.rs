//! AMR-WB serial-parameter bit reader (3GPP TS 26.173 `bits.c` `Serial_parm`), ported bit-exact.
//!
//! The decoder consumes its parameters from a flat array of bit words, MSB-first, advancing a
//! cursor as each field is read (the C reference passes `Word16 **prms` and post-increments it).
//! Each bit word is the reference's `BIT_1` (`+127`) or `BIT_0` (anything else, in practice
//! `−127`). This is the *encoder output order* — exactly the bit order stored in the G.192 `.cod`
//! file — not the RTP-sorted order (which `payload.rs` un-sorts before reaching here).

use crate::amr::basic_ops::{add, shl};

/// The reference's `BIT_1` marker (`+127`); any other value is treated as `BIT_0`.
pub const BIT_1: i16 = 127;
/// The reference's `BIT_0` marker (`−127`).
pub const BIT_0: i16 = -127;

/// RFC 4867 §Annex bit re-ordering for AMR-WB mode 0 (6.60 kbit/s), 132 bits (`sort_660`).
///
/// In an RTP payload the speech bits are stored sorted by subjective importance; the core decoder
/// instead consumes them in encoder/`Bits2prm` order. `SORT_660[i]` is the *encoder-order* index
/// of the `i`-th payload bit (the reference packs as `prms[sort_ptr[i]] = payload_bit_i`).
#[rustfmt::skip]
pub static SORT_660: [u8; 132] = [
      0,   5,   6,   7,  61,  84, 107, 130,  62,  85,
      8,   4,  37,  38,  39,  40,  58,  81, 104, 127,
     60,  83, 106, 129, 108, 131, 128,  41,  42,  80,
    126,   1,   3,  57, 103,  82, 105,  59,   2,  63,
    109, 110,  86,  19,  22,  23,  64,  87,  18,  20,
     21,  17,  13,  88,  43,  89,  65, 111,  14,  24,
     25,  26,  27,  28,  15,  16,  44,  90,  66, 112,
      9,  11,  10,  12,  67, 113,  29,  30,  31,  32,
     34,  33,  35,  36,  45,  51,  68,  74,  91,  97,
    114, 120,  46,  69,  92, 115,  52,  75,  98, 121,
     47,  70,  93, 116,  53,  76,  99, 122,  48,  71,
     94, 117,  54,  77, 100, 123,  49,  72,  95, 118,
     55,  78, 101, 124,  50,  73,  96, 119,  56,  79,
    102, 125,
];

/// Un-sort 132 RTP-payload bits (MSB-first in `data`) into encoder-order `BIT_0`/`BIT_1` words for
/// the core mode-0 decoder (`SORT_660`). `data` must hold at least 17 bytes (132 bits).
#[must_use]
pub fn unsort_mode0(data: &[u8]) -> [i16; 132] {
    let mut prms = [BIT_0; 132];
    for (i, &dest) in SORT_660.iter().enumerate() {
        let byte = data.get(i / 8).copied().unwrap_or(0);
        let bit = (byte >> (7 - (i % 8))) & 1;
        prms[dest as usize] = if bit != 0 { BIT_1 } else { BIT_0 };
    }
    prms
}

/// A forward, MSB-first cursor over a slice of AMR-WB bit words.
#[derive(Debug)]
pub struct SerialBits<'a> {
    bits: &'a [i16],
    pos: usize,
}

impl<'a> SerialBits<'a> {
    /// Wrap a parameter bit slice at offset 0.
    #[must_use]
    pub fn new(bits: &'a [i16]) -> Self {
        Self { bits, pos: 0 }
    }

    /// Read `no_of_bits` bits MSB-first into an unsigned value (`Serial_parm`).
    ///
    /// Out-of-range reads (a malformed/truncated frame) consume the missing bits as `BIT_0`, never
    /// panicking — the caller validates the frame length before trusting the result.
    pub fn read(&mut self, no_of_bits: i16) -> i16 {
        let mut value = 0i16;
        for _ in 0..no_of_bits {
            value = shl(value, 1);
            let bit = self.bits.get(self.pos).copied().unwrap_or(BIT_0);
            self.pos += 1;
            if bit == BIT_1 {
                value = add(value, 1);
            }
        }
        value
    }

    /// Number of bit words consumed so far.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Whether the cursor has read past the end of the underlying slice.
    #[must_use]
    pub fn overran(&self) -> bool {
        self.pos > self.bits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits_from(word: u16, n: i16) -> Vec<i16> {
        // MSB-first expansion of the low `n` bits of `word`.
        (0..n)
            .rev()
            .map(|i| if (word >> i) & 1 == 1 { BIT_1 } else { BIT_0 })
            .collect()
    }

    #[test]
    fn reads_msb_first() {
        // 0b1011 over 4 bits → 11.
        let bits = bits_from(0b1011, 4);
        let mut cursor = SerialBits::new(&bits);
        assert_eq!(cursor.read(4), 0b1011);
        assert_eq!(cursor.position(), 4);
    }

    #[test]
    fn reads_consecutive_fields_in_order() {
        // 8-bit 0xA5 then 4-bit 0x3.
        let mut bits = bits_from(0xA5, 8);
        bits.extend(bits_from(0x3, 4));
        let mut cursor = SerialBits::new(&bits);
        assert_eq!(cursor.read(8), 0xA5);
        assert_eq!(cursor.read(4), 0x3);
        assert_eq!(cursor.position(), 12);
    }

    #[test]
    fn non_bit1_words_are_zero() {
        // Only +127 counts as a 1; -127 (and anything else) is a 0.
        let bits = [BIT_0, BIT_1, BIT_0, BIT_1];
        let mut cursor = SerialBits::new(&bits);
        assert_eq!(cursor.read(4), 0b0101);
    }

    #[test]
    fn truncated_reads_pad_with_zero_without_panicking() {
        let bits = [BIT_1, BIT_1];
        let mut cursor = SerialBits::new(&bits);
        // Reading 4 bits from a 2-bit slice: 11 then two padded zeros → 0b1100.
        assert_eq!(cursor.read(4), 0b1100);
        assert!(cursor.overran());
    }

    #[test]
    fn sort_660_is_a_permutation_of_0_131() {
        // The RFC 4867 mode-0 sort table must be a bijection over 0..132.
        let mut seen = [false; 132];
        for &d in SORT_660.iter() {
            assert!(!seen[d as usize], "duplicate index {d}");
            seen[d as usize] = true;
        }
        assert!(seen.iter().all(|&s| s), "every index 0..132 is covered");
    }

    #[test]
    fn unsort_inverts_the_payload_sort() {
        // Encoder-order bits → RTP-sorted payload bytes → unsort_mode0 → encoder order again.
        // Use a deterministic pattern so each encoder-order position is distinguishable.
        let enc: Vec<i16> = (0..132)
            .map(|i| if i % 3 == 0 { BIT_1 } else { BIT_0 })
            .collect();

        // Sort into payload bit order: payload_bit[i] = enc[SORT_660[i]].
        let mut payload = [0u8; 17];
        for (i, &src) in SORT_660.iter().enumerate() {
            if enc[src as usize] == BIT_1 {
                payload[i / 8] |= 1 << (7 - (i % 8));
            }
        }

        let recovered = unsort_mode0(&payload);
        assert_eq!(&recovered[..], &enc[..], "unsort recovers encoder order");
    }
}
