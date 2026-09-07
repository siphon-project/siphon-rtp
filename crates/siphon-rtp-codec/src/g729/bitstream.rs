//! The 80-bit G.729 frame: unpacking the octets an RTP payload carries into the eleven transmitted
//! parameters, and the parity check that guards the first subframe's pitch lag.
//!
//! ITU-T G.729 §4 transmits 80 bits per 10 ms frame in this order and these widths (the reference's
//! `bitsno` table in `tab_ld8k.c`, written most-significant bit first by `prm2bits_ld8k`):
//!
//! | bits | parameter |
//! |---|---|
//! | 8 | MA predictor switch (1) + LSP first-stage index (7) |
//! | 10 | LSP second-stage indices, 5 + 5 |
//! | 8 | subframe 1 pitch lag |
//! | 1 | parity over the subframe 1 pitch lag |
//! | 13 | subframe 1 fixed-codebook pulse positions |
//! | 4 | subframe 1 fixed-codebook pulse signs |
//! | 7 | subframe 1 gains (adaptive 4 + fixed 3, jointly coded) |
//! | 5 | subframe 2 pitch lag, relative to subframe 1 |
//! | 13 | subframe 2 fixed-codebook pulse positions |
//! | 4 | subframe 2 fixed-codebook pulse signs |
//! | 7 | subframe 2 gains |
//!
//! Concatenated most-significant bit first, that is exactly the ten octets RFC 3551 §4.5.6 carries
//! for payload type 18, which is why this module reads the payload directly rather than going
//! through the reference's file format. That format — one 16-bit word per bit, behind a sync word
//! and a length — exists so the reference binaries can flag an erased frame by zeroing the words,
//! and is a property of those files, not of the codec. Here a lost frame is what the caller says it
//! is, which is the only thing a jitter buffer can tell us anyway.

use crate::CodecError;

/// Octets in one G.729 frame: 80 bits of parameters, 10 ms of speech.
pub const FRAME_BYTES: usize = 10;

/// Samples one frame decodes to: 10 ms at 8 kHz.
pub const FRAME_SAMPLES: usize = 80;

/// Samples in each of the frame's two subframes.
pub const SUBFRAME_SAMPLES: usize = 40;

/// Width in bits of each transmitted parameter, in wire order — the reference's `bitsno`.
const PARAMETER_BITS: [u32; 11] = [8, 10, 8, 1, 13, 4, 7, 5, 13, 4, 7];

/// The parameters one subframe carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubframeParameters {
    /// Pitch-lag index. Absolute (8 bits) in the first subframe, relative to it (5 bits) in the
    /// second, which is why decoding it needs the first subframe's resolved lag for context.
    pub pitch_lag: u16,
    /// Algebraic-codebook pulse positions, 13 bits.
    pub fixed_positions: u16,
    /// Algebraic-codebook pulse signs, 4 bits.
    pub fixed_signs: u16,
    /// Jointly coded adaptive- and fixed-codebook gains, 7 bits.
    pub gains: u16,
}

/// One decoded G.729 frame's transmitted parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameParameters {
    /// MA predictor switch (bit 7) and LSP first-stage index (bits 6..0), as transmitted — the
    /// reference splits this one 8-bit parameter inside `Lsp_iqua_cs` rather than on the wire.
    pub lsp_stage1: u16,
    /// LSP second-stage indices: the two 5-bit halves of one 10-bit parameter.
    pub lsp_stage2: u16,
    /// The two subframes, in transmission order.
    pub subframes: [SubframeParameters; 2],
    /// The parity bit transmitted alongside the first subframe's pitch lag.
    pub pitch_parity: u16,
}

impl FrameParameters {
    /// Whether the first subframe's pitch lag fails its transmitted parity check (ITU-T G.729
    /// §4.1.1, reference `Check_Parity_Pitch`): odd parity over bits 7..2 of the lag index.
    ///
    /// A failure does not make the frame unusable — the decoder treats it as a corrupted lag and
    /// substitutes the previous subframe's, which is why this is a question about one parameter
    /// rather than a reason to reject the payload.
    #[must_use]
    pub fn pitch_parity_error(&self) -> bool {
        let lag = self.subframes[0].pitch_lag;
        // `sum` starts at 1 and accumulates bits 2..=7 of the index; the transmitted parity is
        // added, and an odd total means the two disagree.
        let mut sum = 1_u16 + self.pitch_parity;
        for shift in 2..=7 {
            sum += (lag >> shift) & 1;
        }
        (sum & 1) != 0
    }
}

/// Unpack one 10-octet G.729 frame into its eleven parameters.
///
/// # Errors
///
/// [`CodecError::Malformed`] when the payload is not exactly [`FRAME_BYTES`] long. Every 80-bit
/// pattern is a decodable frame, so there is nothing else to reject here: an index that addresses a
/// codebook is masked to that codebook's width by construction, and the parity bit is advisory.
pub fn unpack(frame: &[u8]) -> Result<FrameParameters, CodecError> {
    if frame.len() != FRAME_BYTES {
        return Err(CodecError::Malformed(
            "G.729 frame must be exactly 10 octets",
        ));
    }
    let mut reader = BitReader::new(frame);
    let mut parameters = [0_u16; 11];
    for (parameter, bits) in parameters.iter_mut().zip(PARAMETER_BITS) {
        *parameter = reader.read(bits);
    }
    Ok(FrameParameters {
        lsp_stage1: parameters[0],
        lsp_stage2: parameters[1],
        pitch_parity: parameters[3],
        subframes: [
            SubframeParameters {
                pitch_lag: parameters[2],
                fixed_positions: parameters[4],
                fixed_signs: parameters[5],
                gains: parameters[6],
            },
            SubframeParameters {
                pitch_lag: parameters[7],
                fixed_positions: parameters[8],
                fixed_signs: parameters[9],
                gains: parameters[10],
            },
        ],
    })
}

/// Most-significant-bit-first reader over the frame's octets.
struct BitReader<'a> {
    bytes: &'a [u8],
    position: u32,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Read the next `count` bits (`count <= 16`), most significant first. Reads past the end
    /// yield zero bits; [`unpack`] has already fixed the length, so that cannot happen there.
    fn read(&mut self, count: u32) -> u16 {
        let mut value = 0_u16;
        for _ in 0..count {
            let index = (self.position / 8) as usize;
            let bit = self
                .bytes
                .get(index)
                .map_or(0, |byte| (byte >> (7 - self.position % 8)) & 1);
            value = (value << 1) | u16::from(bit);
            self.position += 1;
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pack eleven parameters back into the wire octets, so a test can build a frame from named
    /// values instead of a hex literal. Test-only: the decoder never writes a bitstream.
    fn pack(parameters: [u16; 11]) -> [u8; FRAME_BYTES] {
        let mut frame = [0_u8; FRAME_BYTES];
        let mut position = 0_u32;
        for (value, bits) in parameters.into_iter().zip(PARAMETER_BITS) {
            for bit_index in (0..bits).rev() {
                if (value >> bit_index) & 1 == 1 {
                    frame[(position / 8) as usize] |= 1 << (7 - position % 8);
                }
                position += 1;
            }
        }
        assert_eq!(position, 80, "the frame is exactly 80 bits");
        frame
    }

    #[test]
    fn the_eleven_parameters_occupy_exactly_eighty_bits() {
        assert_eq!(PARAMETER_BITS.iter().sum::<u32>(), 80);
        assert_eq!(FRAME_BYTES * 8, 80);
    }

    #[test]
    fn a_frame_that_is_not_ten_octets_is_rejected() {
        assert!(matches!(unpack(&[]), Err(CodecError::Malformed(_))));
        assert!(matches!(unpack(&[0; 9]), Err(CodecError::Malformed(_))));
        assert!(matches!(unpack(&[0; 11]), Err(CodecError::Malformed(_))));
        assert!(
            unpack(&[0; FRAME_BYTES]).is_ok(),
            "any 80-bit pattern decodes"
        );
    }

    #[test]
    fn each_parameter_is_read_from_its_own_field_at_its_own_width() {
        // Every field set to its maximum in turn: a misplaced boundary shows up as a neighbour
        // picking up bits, which a single all-ones frame would hide.
        let widths = PARAMETER_BITS;
        for (index, bits) in widths.into_iter().enumerate() {
            let mut parameters = [0_u16; 11];
            parameters[index] = ((1_u32 << bits) - 1) as u16;
            let unpacked = unpack(&pack(parameters)).expect("ten octets");
            let read_back = [
                unpacked.lsp_stage1,
                unpacked.lsp_stage2,
                unpacked.subframes[0].pitch_lag,
                unpacked.pitch_parity,
                unpacked.subframes[0].fixed_positions,
                unpacked.subframes[0].fixed_signs,
                unpacked.subframes[0].gains,
                unpacked.subframes[1].pitch_lag,
                unpacked.subframes[1].fixed_positions,
                unpacked.subframes[1].fixed_signs,
                unpacked.subframes[1].gains,
            ];
            assert_eq!(read_back, parameters, "parameter {index} at {bits} bits");
        }
    }

    #[test]
    fn the_first_octet_is_the_lsp_parameter_most_significant_bit_first() {
        // Pins the bit order against the wire rather than against this module's own writer: the
        // 8-bit LSP parameter is the first field, so it is octet 0 exactly.
        let frame = pack([0b1010_0101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(frame[0], 0b1010_0101);
        assert_eq!(unpack(&frame).expect("frame").lsp_stage1, 0b1010_0101);
    }

    #[test]
    fn pitch_parity_is_odd_over_bits_two_to_seven_of_the_lag() {
        // The reference seeds the sum at 1 and folds in bits 7..2 of the lag index, so the parity
        // bit that makes the total even is the one that agrees.
        for lag in 0..256_u16 {
            let ones = (2..=7).map(|shift| (lag >> shift) & 1).sum::<u16>();
            let agreeing_parity = (1 + ones) & 1;
            let mut parameters = [0_u16; 11];
            parameters[2] = lag;
            parameters[3] = agreeing_parity;
            let frame = unpack(&pack(parameters)).expect("frame");
            assert!(
                !frame.pitch_parity_error(),
                "lag {lag} with matching parity"
            );

            parameters[3] = agreeing_parity ^ 1;
            let frame = unpack(&pack(parameters)).expect("frame");
            assert!(frame.pitch_parity_error(), "lag {lag} with flipped parity");
        }
    }
}
