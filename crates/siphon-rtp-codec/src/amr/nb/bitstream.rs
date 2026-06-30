//! AMR-NB serial bit (de)packing — 3GPP TS 26.073 `bits2prm.c` / `prm2bits.c` + `bitno.tab`.
//!
//! The encoder/decoder *core* works in **parameter** order: each mode emits a fixed list of
//! integer parameters (`prm[]`), and each parameter occupies a fixed number of serial bits given by
//! [`BITNO`]. [`bits2prm`] turns the flat serial-bit array (one bit per word, MSB-first within a
//! field) into the parameter vector; [`prm2bits`] is the inverse. This is exactly the order stored
//! in the official `.COD` test vectors (one `Word16` per bit, value `0`/`1`), **not** the
//! RTP-sorted, octet-packed order (RFC 4867 §4) — the [`SORT`] tables and [`unsort`]/[`pack`] handle
//! that conversion on the RTP path.
//!
//! AMR-NB's `BIT_0`/`BIT_1` are `0`/`1` (`bitno.tab`), unlike AMR-WB's `±127`.

/// The reference `BIT_0` marker (`bitno.tab`).
pub const BIT_0: i16 = 0;
/// The reference `BIT_1` marker (`bitno.tab`).
pub const BIT_1: i16 = 1;

/// Maximum number of serial speech bits across all modes (MR122). `cnst.h` `MAX_SERIAL_SIZE`.
pub const MAX_SERIAL_SIZE: usize = 244;
/// Maximum number of parameters across all modes (MR122). `cnst.h` `MAX_PRM_SIZE`.
pub const MAX_PRM_SIZE: usize = 57;

/// Number of parameters per mode, indexed by [`crate::amr::AmrNbMode`] frame type 0..=7
/// (`bitno.tab` `prmno`). The trailing entry (index 8) is `MRDTX`.
pub const PRMNO: [usize; 9] = [17, 19, 19, 19, 19, 23, 39, 57, 5];

/// Number of bits per parameter, one table per mode (`bitno.tab` `bitno_MR*`).
/// Index 0..=7 are the speech modes; index 8 is `MRDTX`.
#[rustfmt::skip]
pub static BITNO: [&[i16]; 9] = [
    // MR475 (17 params)
    &[8, 8, 7,
      8, 7, 2, 8,
      4, 7, 2,
      4, 7, 2, 8,
      4, 7, 2],
    // MR515 (19)
    &[8, 8, 7,
      8, 7, 2, 6,
      4, 7, 2, 6,
      4, 7, 2, 6,
      4, 7, 2, 6],
    // MR59 (19)
    &[8, 9, 9,
      8, 9, 2, 6,
      4, 9, 2, 6,
      8, 9, 2, 6,
      4, 9, 2, 6],
    // MR67 (19)
    &[8, 9, 9,
      8, 11, 3, 7,
      4, 11, 3, 7,
      8, 11, 3, 7,
      4, 11, 3, 7],
    // MR74 (19)
    &[8, 9, 9,
      8, 13, 4, 7,
      5, 13, 4, 7,
      8, 13, 4, 7,
      5, 13, 4, 7],
    // MR795 (23)
    &[9, 9, 9,
      8, 13, 4, 4, 5,
      6, 13, 4, 4, 5,
      8, 13, 4, 4, 5,
      6, 13, 4, 4, 5],
    // MR102 (39)
    &[8, 9, 9,
      8, 1, 1, 1, 1, 10, 10, 7, 7,
      5, 1, 1, 1, 1, 10, 10, 7, 7,
      8, 1, 1, 1, 1, 10, 10, 7, 7,
      5, 1, 1, 1, 1, 10, 10, 7, 7],
    // MR122 (57)
    &[7, 8, 9, 8, 6,
      9, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5,
      6, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5,
      9, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5,
      6, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 5],
    // MRDTX (5)
    &[3, 8, 9, 9, 6],
];

/// Read `no_of_bits` from `bitstream` (MSB first) and convert to an integer
/// (`bits2prm.c` `Bin2int`). `BIT_1` contributes a 1 bit; anything else a 0 bit.
fn bin2int(no_of_bits: i16, bitstream: &[i16]) -> i16 {
    let mut value: i16 = 0;
    for &bit in bitstream.iter().take(no_of_bits as usize) {
        value <<= 1;
        if bit == BIT_1 {
            value += 1;
        }
    }
    value
}

/// Convert `value` to `no_of_bits` binary bits, MSB first, writing `BIT_0`/`BIT_1`
/// (`prm2bits.c` `Int2bin`).
fn int2bin(value: i16, no_of_bits: i16, bitstream: &mut [i16]) {
    let n = no_of_bits as usize;
    let mut value = value;
    // Write LSB-first into the tail, exactly as the reference fills `&bitstream[no_of_bits]` and
    // walks backward.
    for i in (0..n).rev() {
        bitstream[i] = if value & 0x0001 != 0 { BIT_1 } else { BIT_0 };
        value >>= 1;
    }
}

/// Retrieve the parameter vector from the serial speech bits of one frame for `mode`
/// (`bits2prm.c` `Bits2prm`). `mode` is the [`crate::amr::AmrNbMode`] frame type (0..=7) or `8`
/// for `MRDTX`. Returns the `PRMNO[mode]` decoded parameters.
#[must_use]
pub fn bits2prm(mode: usize, bits: &[i16]) -> [i16; MAX_PRM_SIZE] {
    let mut prm = [0i16; MAX_PRM_SIZE];
    let bitno = BITNO[mode];
    let mut cursor = 0usize;
    for (index, &nbits) in bitno.iter().enumerate().take(PRMNO[mode]) {
        prm[index] = bin2int(nbits, &bits[cursor..]);
        cursor += nbits as usize;
    }
    prm
}

/// Convert a parameter vector into serial speech bits for `mode` (`prm2bits.c` `Prm2bits`).
/// Writes `sum(BITNO[mode])` bits into `bits`.
pub fn prm2bits(mode: usize, prm: &[i16], bits: &mut [i16]) {
    let bitno = BITNO[mode];
    let mut cursor = 0usize;
    for (index, &nbits) in bitno.iter().enumerate().take(PRMNO[mode]) {
        int2bin(
            prm[index],
            nbits,
            &mut bits[cursor..cursor + nbits as usize],
        );
        cursor += nbits as usize;
    }
}

/// Total number of serial speech bits for `mode` (sum of [`BITNO`]; equals
/// [`crate::amr::AMRNB_SPEECH_BITS`] for speech modes).
#[must_use]
pub fn serial_bits(mode: usize) -> usize {
    BITNO[mode]
        .iter()
        .take(PRMNO[mode])
        .map(|&b| b as usize)
        .sum()
}

/// RFC 4867 §4 bit-reorder ("sort") tables for the RTP bandwidth-efficient / octet-aligned payload,
/// indexed by speech-mode frame type 0..=7 (`bitno.tab` `sort_*`). Entry `i` is the index into the
/// encoder-order serial-bit array that supplies RTP payload bit `i`.
#[rustfmt::skip]
pub static SORT: [&[u16]; 8] = [
    // sort_475 (95)
    &[ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
      10, 11, 12, 13, 14, 15, 23, 24, 25, 26,
      27, 28, 48, 49, 61, 62, 82, 83, 47, 46,
      45, 44, 81, 80, 79, 78, 17, 18, 20, 22,
      77, 76, 75, 74, 29, 30, 43, 42, 41, 40,
      38, 39, 16, 19, 21, 50, 51, 59, 60, 63,
      64, 72, 73, 84, 85, 93, 94, 32, 33, 35,
      36, 53, 54, 56, 57, 66, 67, 69, 70, 87,
      88, 90, 91, 34, 55, 68, 89, 37, 58, 71,
      92, 31, 52, 65, 86],
    // sort_515 (103)
    &[ 7,  6,  5,   4,   3,   2,  1,  0, 15, 14,
      13, 12, 11,  10,   9,   8, 23, 24, 25, 26,
      27, 46, 65,  84,  45,  44, 43, 64, 63, 62,
      83, 82, 81, 102, 101, 100, 42, 61, 80, 99,
      28, 47, 66,  85,  18,  41, 60, 79, 98, 29,
      48, 67, 17,  20,  22,  40, 59, 78, 97, 21,
      30, 49, 68,  86,  19,  16, 87, 39, 38, 58,
      57, 77, 35,  54,  73,  92, 76, 96, 95, 36,
      55, 74, 93,  32,  51,  33, 52, 70, 71, 89,
      90, 31, 50,  69,  88,  37, 56, 75, 94, 34,
      53, 72, 91],
    // sort_59 (118)
    &[  0,   1,   4,   5,   3,   6,   7,   2,  13,  15,
        8,   9,  11,  12,  14,  10,  16,  28,  74,  29,
       75,  27,  73,  26,  72,  30,  76,  51,  97,  50,
       71,  96, 117,  31,  77,  52,  98,  49,  70,  95,
      116,  53,  99,  32,  78,  33,  79,  48,  69,  94,
      115,  47,  68,  93, 114,  46,  67,  92, 113,  19,
       21,  23,  22,  18,  17,  20,  24, 111,  43,  89,
      110,  64,  65,  44,  90,  25,  45,  66,  91, 112,
       54, 100,  40,  61,  86, 107,  39,  60,  85, 106,
       36,  57,  82, 103,  35,  56,  81, 102,  34,  55,
       80, 101,  42,  63,  88, 109,  41,  62,  87, 108,
       38,  59,  84, 105,  37,  58,  83, 104],
    // sort_67 (134)
    &[  0,   1,   4,   3,   5,   6,  13,   7,   2,   8,
        9,  11,  15,  12,  14,  10,  28,  82,  29,  83,
       27,  81,  26,  80,  30,  84,  16,  55, 109,  56,
      110,  31,  85,  57, 111,  48,  73, 102, 127,  32,
       86,  51,  76, 105, 130,  52,  77, 106, 131,  58,
      112,  33,  87,  19,  23,  53,  78, 107, 132,  21,
       22,  18,  17,  20,  24,  25,  50,  75, 104, 129,
       47,  72, 101, 126,  54,  79, 108, 133,  46,  71,
      100, 125, 128, 103,  74,  49,  45,  70,  99, 124,
       42,  67,  96, 121,  39,  64,  93, 118,  38,  63,
       92, 117,  35,  60,  89, 114,  34,  59,  88, 113,
       44,  69,  98, 123,  43,  68,  97, 122,  41,  66,
       95, 120,  40,  65,  94, 119,  37,  62,  91, 116,
       36,  61,  90, 115],
    // sort_74 (148)
    &[  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
       10,  11,  12,  13,  14,  15,  16,  26,  87,  27,
       88,  28,  89,  29,  90,  30,  91,  51,  80, 112,
      141,  52,  81, 113, 142,  54,  83, 115, 144,  55,
       84, 116, 145,  58, 119,  59, 120,  21,  22,  23,
       17,  18,  19,  31,  60,  92, 121,  56,  85, 117,
      146,  20,  24,  25,  50,  79, 111, 140,  57,  86,
      118, 147,  49,  78, 110, 139,  48,  77,  53,  82,
      114, 143, 109, 138,  47,  76, 108, 137,  32,  33,
       61,  62,  93,  94, 122, 123,  41,  42,  43,  44,
       45,  46,  70,  71,  72,  73,  74,  75, 102, 103,
      104, 105, 106, 107, 131, 132, 133, 134, 135, 136,
       34,  63,  95, 124,  35,  64,  96, 125,  36,  65,
       97, 126,  37,  66,  98, 127,  38,  67,  99, 128,
       39,  68, 100, 129,  40,  69, 101, 130],
    // sort_795 (159)
    &[  8,   7,   6,   5,   4,   3,   2,  14,  16,   9,
       10,  12,  13,  15,  11,  17,  20,  22,  24,  23,
       19,  18,  21,  56,  88, 122, 154,  57,  89, 123,
      155,  58,  90, 124, 156,  52,  84, 118, 150,  53,
       85, 119, 151,  27,  93,  28,  94,  29,  95,  30,
       96,  31,  97,  61, 127,  62, 128,  63, 129,  59,
       91, 125, 157,  32,  98,  64, 130,   1,   0,  25,
       26,  33,  99,  34, 100,  65, 131,  66, 132,  54,
       86, 120, 152,  60,  92, 126, 158,  55,  87, 121,
      153, 117, 116, 115,  46,  78, 112, 144,  43,  75,
      109, 141,  40,  72, 106, 138,  36,  68, 102, 134,
      114, 149, 148, 147, 146,  83,  82,  81,  80,  51,
       50,  49,  48,  47,  45,  44,  42,  39,  35,  79,
       77,  76,  74,  71,  67, 113, 111, 110, 108, 105,
      101, 145, 143, 142, 140, 137, 133,  41,  73, 107,
      139,  37,  69, 103, 135,  38,  70, 104, 136],
    // sort_102 (204)
    &[  7,   6,   5,   4,   3,   2,   1,   0,  16,  15,
       14,  13,  12,  11,  10,   9,   8,  26,  27,  28,
       29,  30,  31, 115, 116, 117, 118, 119, 120,  72,
       73, 161, 162,  65,  68,  69, 108, 111, 112, 154,
      157, 158, 197, 200, 201,  32,  33, 121, 122,  74,
       75, 163, 164,  66, 109, 155, 198,  19,  23,  21,
       22,  18,  17,  20,  24,  25,  37,  36,  35,  34,
       80,  79,  78,  77, 126, 125, 124, 123, 169, 168,
      167, 166,  70,  67,  71, 113, 110, 114, 159, 156,
      160, 202, 199, 203,  76, 165,  81,  82,  92,  91,
       93,  83,  95,  85,  84,  94, 101, 102,  96, 104,
       86, 103,  87,  97, 127, 128, 138, 137, 139, 129,
      141, 131, 130, 140, 147, 148, 142, 150, 132, 149,
      133, 143, 170, 171, 181, 180, 182, 172, 184, 174,
      173, 183, 190, 191, 185, 193, 175, 192, 176, 186,
       38,  39,  49,  48,  50,  40,  52,  42,  41,  51,
       58,  59,  53,  61,  43,  60,  44,  54, 194, 179,
      189, 196, 177, 195, 178, 187, 188, 151, 136, 146,
      153, 134, 152, 135, 144, 145, 105,  90, 100, 107,
       88, 106,  89,  98,  99,  62,  47,  57,  64,  45,
       63,  46,  55,  56],
    // sort_122 (244)
    &[  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
       10,  11,  12,  13,  14,  23,  15,  16,  17,  18,
       19,  20,  21,  22,  24,  25,  26,  27,  28,  38,
      141,  39, 142,  40, 143,  41, 144,  42, 145,  43,
      146,  44, 147,  45, 148,  46, 149,  47,  97, 150,
      200,  48,  98, 151, 201,  49,  99, 152, 202,  86,
      136, 189, 239,  87, 137, 190, 240,  88, 138, 191,
      241,  91, 194,  92, 195,  93, 196,  94, 197,  95,
      198,  29,  30,  31,  32,  33,  34,  35,  50, 100,
      153, 203,  89, 139, 192, 242,  51, 101, 154, 204,
       55, 105, 158, 208,  90, 140, 193, 243,  59, 109,
      162, 212,  63, 113, 166, 216,  67, 117, 170, 220,
       36,  37,  54,  53,  52,  58,  57,  56,  62,  61,
       60,  66,  65,  64,  70,  69,  68, 104, 103, 102,
      108, 107, 106, 112, 111, 110, 116, 115, 114, 120,
      119, 118, 157, 156, 155, 161, 160, 159, 165, 164,
      163, 169, 168, 167, 173, 172, 171, 207, 206, 205,
      211, 210, 209, 215, 214, 213, 219, 218, 217, 223,
      222, 221,  73,  72,  71,  76,  75,  74,  79,  78,
       77,  82,  81,  80,  85,  84,  83, 123, 122, 121,
      126, 125, 124, 129, 128, 127, 132, 131, 130, 135,
      134, 133, 176, 175, 174, 179, 178, 177, 182, 181,
      180, 185, 184, 183, 188, 187, 186, 226, 225, 224,
      229, 228, 227, 232, 231, 230, 235, 234, 233, 238,
      237, 236,  96, 199],
];

/// Un-sort one octet-packed RFC 4867 speech frame back into encoder/`bits2prm` order, returning a
/// serial-bit array (`0`/`1`) of length [`serial_bits`]`(mode)`. `data` holds the speech bits
/// MSB-first (bit 0 = MSB of `data[0]`); `mode` is the speech-mode frame type (0..=7).
#[must_use]
pub fn unsort(data: &[u8], mode: usize) -> [i16; MAX_SERIAL_SIZE] {
    let mut bits = [BIT_0; MAX_SERIAL_SIZE];
    let sort = SORT[mode];
    for (i, &dst) in sort.iter().enumerate() {
        let byte = data[i / 8];
        let bit = (byte >> (7 - (i % 8))) & 1;
        bits[dst as usize] = if bit != 0 { BIT_1 } else { BIT_0 };
    }
    bits
}

/// Sort + pack a serial-bit array (`bits`, encoder/`bits2prm` order, `0`/`1`) into the octet-packed
/// RFC 4867 speech-frame body for `mode` (the inverse of [`unsort`]). Returns
/// `ceil(serial_bits(mode) / 8)` bytes, MSB-first.
#[must_use]
pub fn pack(bits: &[i16], mode: usize) -> Vec<u8> {
    let sort = SORT[mode];
    let mut data = vec![0u8; sort.len().div_ceil(8)];
    for (i, &src) in sort.iter().enumerate() {
        if bits[src as usize] == BIT_1 {
            data[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amr::AMRNB_SPEECH_BITS;

    #[test]
    fn serial_bit_counts_match_rfc_4867_table() {
        for (mode, &expected) in AMRNB_SPEECH_BITS.iter().enumerate() {
            assert_eq!(
                serial_bits(mode),
                expected as usize,
                "mode {mode} serial-bit total must equal RFC 4867 Table 1"
            );
        }
        // MRDTX (SID): 3 + 8 + 9 + 9 + 6 = 35 (the unpacked SID size; the 39 in the RFC table
        // includes 4 extra bits not in the serial core).
        assert_eq!(serial_bits(8), 35);
    }

    #[test]
    fn bin2int_is_msb_first() {
        // 0b101 = 5, MSB first.
        assert_eq!(bin2int(3, &[BIT_1, BIT_0, BIT_1]), 5);
        assert_eq!(bin2int(4, &[BIT_1, BIT_1, BIT_1, BIT_1]), 15);
        assert_eq!(bin2int(1, &[BIT_0]), 0);
    }

    #[test]
    fn int2bin_is_msb_first() {
        let mut bits = [BIT_0; 3];
        int2bin(5, 3, &mut bits);
        assert_eq!(bits, [BIT_1, BIT_0, BIT_1]);
    }

    #[test]
    fn prm_bits_roundtrip_all_modes() {
        for mode in 0..8usize {
            let nbits = serial_bits(mode);
            // Deterministic parameter pattern within each field's range.
            let mut prm = [0i16; MAX_PRM_SIZE];
            for (index, p) in prm.iter_mut().enumerate().take(PRMNO[mode]) {
                let field_bits = BITNO[mode][index];
                let max = (1i32 << field_bits) - 1;
                *p = (((index as i32 * 37 + 11) % (max + 1)) as i16).max(0);
            }
            let mut bits = [BIT_0; MAX_SERIAL_SIZE];
            prm2bits(mode, &prm, &mut bits[..nbits]);
            let decoded = bits2prm(mode, &bits);
            assert_eq!(
                &decoded[..PRMNO[mode]],
                &prm[..PRMNO[mode]],
                "mode {mode} prm roundtrip"
            );
        }
    }

    #[test]
    fn unsort_pack_roundtrip_all_modes() {
        for mode in 0..8usize {
            let nbits = serial_bits(mode);
            // Pseudo-random serial bits.
            let mut bits = [BIT_0; MAX_SERIAL_SIZE];
            let mut seed: u32 = 0x1234_5678;
            for b in bits.iter_mut().take(nbits) {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                *b = if (seed >> 16) & 1 != 0 { BIT_1 } else { BIT_0 };
            }
            let packed = pack(&bits, mode);
            assert_eq!(packed.len(), nbits.div_ceil(8));
            let unpacked = unsort(&packed, mode);
            assert_eq!(
                &unpacked[..nbits],
                &bits[..nbits],
                "mode {mode} sort/pack roundtrip"
            );
        }
    }

    #[test]
    fn sort_tables_have_expected_lengths() {
        let lens = [95, 103, 118, 134, 148, 159, 204, 244];
        for (mode, &len) in lens.iter().enumerate() {
            assert_eq!(SORT[mode].len(), len, "mode {mode} sort table length");
        }
    }
}
