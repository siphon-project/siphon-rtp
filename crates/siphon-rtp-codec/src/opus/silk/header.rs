//! LP-layer header: VAD flags, the LBRR flag, and the per-frame LBRR flags
//! (RFC 6716 §4.2.3-§4.2.4; libopus `dec_API.c:228-250`).
//!
//! These are the very first symbols of the SILK layer, before any SILK frame. Their count is not
//! carried in the bitstream — it follows from the Opus TOC alone (channel count and frame duration),
//! which is why [`LpLayerHeader::decode`] takes both as arguments rather than discovering them.
//!
//! Bitstream order, and the trap it contains: the VAD flags and LBRR flag are read **per channel,
//! interleaved as (mid flags, mid LBRR), (side flags, side LBRR)** — and only *then* are the
//! per-frame LBRR flags read for both channels (RFC 6716 Figure 16). Reading the mid channel's
//! per-frame LBRR flags immediately after its global flag, which is the intuitive grouping, puts
//! every subsequent symbol in the packet at the wrong offset.

use crate::opus::range_coder::RangeDecoder;
use crate::opus::silk::decoder::SilkDecoder;
use crate::opus::silk::tables::{LBRR_FLAGS_2_ICDF, LBRR_FLAGS_3_ICDF, VAD_FLAG_LOG_PROBABILITY};
use crate::opus::silk::types::MAX_FRAMES_PER_PACKET;
use crate::CodecError;

/// `ftb` for every SILK ICDF symbol: they all have total frequency 256.
const ICDF_FTB: u32 = 8;

/// One channel's LP-layer header flags (libopus `silk_decoder_state.VAD_flags` / `LBRR_flag` /
/// `LBRR_flags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelFlags {
    /// One VAD flag per 20 ms SILK frame in this Opus frame; entries beyond
    /// `frames_per_packet` stay `false`. A clear flag makes that SILK frame "inactive", which
    /// selects the narrower frame-type PDF (§4.2.7.3) and, in a stereo packet, is what allows the
    /// mid-only flag to appear at all (§4.2.7.2).
    pub vad_flags: [bool; MAX_FRAMES_PER_PACKET],
    /// The channel carries at least one LBRR frame (RFC 6716 §4.2.3).
    pub lbrr_flag: bool,
    /// Which 20 ms intervals carry an LBRR frame (RFC 6716 §4.2.4). For a 10/20 ms Opus frame this is
    /// just `lbrr_flag` in slot 0 — there is at most one LBRR frame per channel, so no symbol is
    /// coded.
    pub lbrr_flags: [bool; MAX_FRAMES_PER_PACKET],
}

impl ChannelFlags {
    /// Whether the SILK frame at `frame_index` is "active" for frame-type purposes — the C's
    /// `decode_LBRR || psDec->VAD_flags[FrameIndex]` (`decode_indices.c:51`).
    ///
    /// An LBRR frame is *always* active: RFC 6716 §4.2.5 states LBRR frames are only transmitted for
    /// active speech and carry no VAD flags of their own.
    #[must_use]
    pub fn is_active(&self, frame_index: usize, is_lbrr: bool) -> bool {
        is_lbrr || self.vad_flags.get(frame_index).copied().unwrap_or(false)
    }
}

/// The decoded LP-layer header for a whole Opus frame (RFC 6716 §4.2.3-§4.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpLayerHeader {
    /// Flags per internal channel: index 0 is mid, index 1 is side. The side entry is left at its
    /// default when the stream is mono.
    pub channels: [ChannelFlags; 2],
    /// Internal channel count these flags were decoded for (1 or 2).
    pub channel_count: usize,
    /// 20 ms SILK frames per Opus frame (1, 2, or 3) — how many VAD flags each channel carries.
    pub frames_per_packet: usize,
}

impl LpLayerHeader {
    /// Decode the LP-layer header (libopus `dec_API.c:228-250`).
    ///
    /// `channel_count` comes from the TOC stereo flag and `frames_per_packet` from the frame duration
    /// (see [`super::types::SubframeLayout`]). Two to eight header bits are consumed, plus one ICDF
    /// symbol per channel that has LBRR data in a 40/60 ms frame.
    pub fn decode(
        decoder: &mut RangeDecoder<'_>,
        channel_count: usize,
        frames_per_packet: usize,
    ) -> Result<Self, CodecError> {
        if channel_count != 1 && channel_count != 2 {
            return Err(CodecError::Unsupported(
                "silk: internal channels must be 1 or 2",
            ));
        }
        if frames_per_packet == 0 || frames_per_packet > MAX_FRAMES_PER_PACKET {
            return Err(CodecError::Unsupported(
                "silk: frames per packet must be 1, 2 or 3",
            ));
        }

        let mut channels = [ChannelFlags::default(); 2];

        // Pass 1: one VAD flag per SILK frame, then the global LBRR flag — for each channel in turn
        // (dec_API.c:231-236). Both are single bits with uniform probability (RFC 6716 Table 3).
        for channel in channels.iter_mut().take(channel_count) {
            for frame_index in 0..frames_per_packet {
                channel.vad_flags[frame_index] = decoder.dec_bit_logp(VAD_FLAG_LOG_PROBABILITY);
            }
            channel.lbrr_flag = decoder.dec_bit_logp(VAD_FLAG_LOG_PROBABILITY);
        }

        // Pass 2: the per-frame LBRR flags, again for each channel in turn (dec_API.c:238-250).
        for channel in channels.iter_mut().take(channel_count) {
            if !channel.lbrr_flag {
                continue;
            }
            if frames_per_packet == 1 {
                // 10/20 ms: at most one LBRR frame per channel, so the global flag says it all and
                // no symbol is coded (RFC 6716 §4.2.4).
                channel.lbrr_flags[0] = true;
                continue;
            }
            // 40/60 ms: one symbol codes the whole bit pattern. The table starts at symbol 1 — the
            // all-zero pattern is impossible here, since `lbrr_flag` is already set — hence `+ 1`.
            let icdf: &[u8] = if frames_per_packet == 2 {
                &LBRR_FLAGS_2_ICDF
            } else {
                &LBRR_FLAGS_3_ICDF
            };
            let symbol = decoder.dec_icdf(icdf, ICDF_FTB) + 1;
            // "the resulting 2- or 3-bit integer contains the corresponding LBRR flag for each
            // frame, packed in order from the LSB to the MSB" (RFC 6716 §4.2.4).
            for frame_index in 0..frames_per_packet {
                channel.lbrr_flags[frame_index] = (symbol >> frame_index) & 1 == 1;
            }
        }

        Ok(Self {
            channels,
            channel_count,
            frames_per_packet,
        })
    }

    /// Flags for one internal channel (0 = mid, 1 = side).
    pub fn channel(&self, index: usize) -> Result<&ChannelFlags, CodecError> {
        if index >= self.channel_count {
            return Err(CodecError::Unsupported("silk: channel index out of range"));
        }
        self.channels
            .get(index)
            .ok_or(CodecError::Unsupported("silk: channel index out of range"))
    }

    /// Whether any coded channel has any VAD flag set. RFC 6716 §4.2.3 notes this is decidable
    /// straight from the first byte, without the range decoder — a receiver can drop a fully inactive
    /// SILK payload cheaply.
    #[must_use]
    pub fn any_voice_activity(&self) -> bool {
        self.channels
            .iter()
            .take(self.channel_count)
            .any(|channel| channel.vad_flags.iter().any(|&flag| flag))
    }

    /// Whether any coded channel carries LBRR data.
    #[must_use]
    pub fn any_lbrr(&self) -> bool {
        self.channels
            .iter()
            .take(self.channel_count)
            .any(|channel| channel.lbrr_flag)
    }
}

impl SilkDecoder {
    /// Decode the LP-layer header for the current packet and store it on the channel states, the way
    /// `silk_Decode` writes straight into `channel_state[n].VAD_flags` / `LBRR_flags`
    /// (`dec_API.c:231-250`).
    ///
    /// Uses the internal channel count and frames-per-packet from the last
    /// [`SilkDecoder::configure`], so it cannot disagree with the rest of the decoder's view of the
    /// packet. Call once per Opus frame, before any SILK frame is decoded.
    pub fn decode_lp_layer_header(
        &mut self,
        decoder: &mut RangeDecoder<'_>,
    ) -> Result<LpLayerHeader, CodecError> {
        let channel_count = self.channel_count();
        let frames_per_packet = self.channel(0)?.frames_per_packet();
        let header = LpLayerHeader::decode(decoder, channel_count, frames_per_packet)?;
        for index in 0..channel_count {
            let flags = *header.channel(index)?;
            let channel = self.channel_mut(index)?;
            channel.vad_flags = flags.vad_flags;
            channel.lbrr_flag = flags.lbrr_flag;
            channel.lbrr_flags = flags.lbrr_flags;
            channel.frames_decoded = 0;
        }
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opus::range_coder::RangeEncoder;
    use crate::opus::silk::types::InternalRate;

    /// Encode a header the way libopus' encoder would, so the decoder can be driven with a
    /// bit-for-bit legal stream. Mirrors `silk_encode_indices` / `enc_API.c`'s flag ordering.
    fn encode_header(
        vad: &[&[bool]],
        lbrr: &[bool],
        lbrr_symbols: &[Option<u32>],
        buffer: &mut [u8],
    ) -> usize {
        let mut encoder = RangeEncoder::new(buffer);
        for (channel_vad, &channel_lbrr) in vad.iter().zip(lbrr.iter()) {
            for &flag in channel_vad.iter() {
                encoder.enc_bit_logp(flag, VAD_FLAG_LOG_PROBABILITY);
            }
            encoder.enc_bit_logp(channel_lbrr, VAD_FLAG_LOG_PROBABILITY);
        }
        for (index, symbol) in lbrr_symbols.iter().enumerate() {
            if let Some(symbol) = *symbol {
                let icdf: &[u8] = if vad[index].len() == 2 {
                    &LBRR_FLAGS_2_ICDF
                } else {
                    &LBRR_FLAGS_3_ICDF
                };
                encoder.enc_icdf((symbol - 1) as usize, icdf, ICDF_FTB);
            }
        }
        encoder.done();
        assert!(!encoder.error(), "test encoder must not overflow");
        buffer.len()
    }

    #[test]
    fn mono_20ms_single_vad_flag_and_no_lbrr() {
        let mut buffer = [0u8; 64];
        encode_header(&[&[true]], &[false], &[None], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let header = LpLayerHeader::decode(&mut decoder, 1, 1).expect("valid header");
        assert_eq!(header.channel_count, 1);
        assert_eq!(header.frames_per_packet, 1);
        assert_eq!(header.channels[0].vad_flags, [true, false, false]);
        assert!(!header.channels[0].lbrr_flag);
        assert_eq!(header.channels[0].lbrr_flags, [false; 3]);
        assert!(header.any_voice_activity());
        assert!(!header.any_lbrr());
    }

    #[test]
    fn mono_20ms_inactive_frame() {
        let mut buffer = [0u8; 64];
        encode_header(&[&[false]], &[false], &[None], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let header = LpLayerHeader::decode(&mut decoder, 1, 1).expect("valid header");
        assert!(!header.any_voice_activity());
        assert!(!header.channels[0].is_active(0, false));
        // An LBRR frame is active regardless of the VAD flag (RFC 6716 §4.2.5).
        assert!(header.channels[0].is_active(0, true));
    }

    /// A 10/20 ms Opus frame codes **no** per-frame LBRR symbol: the global flag implies slot 0.
    #[test]
    fn single_frame_lbrr_needs_no_symbol() {
        let mut buffer = [0u8; 64];
        encode_header(&[&[true]], &[true], &[None], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let before = decoder.tell();
        let header = LpLayerHeader::decode(&mut decoder, 1, 1).expect("valid header");
        let after = decoder.tell();
        assert_eq!(header.channels[0].lbrr_flags, [true, false, false]);
        // Two bits only: one VAD flag plus the LBRR flag.
        assert_eq!(after - before, 2, "only the two header bits are consumed");
    }

    /// RFC 6716 §4.2.4: the 2-bit integer's bits map LSB-first onto the 20 ms intervals of a 40 ms
    /// Opus frame. Symbols 1..=3 are the three legal patterns.
    #[test]
    fn forty_ms_per_frame_lbrr_flags_are_lsb_first() {
        for (symbol, expected) in [
            (1u32, [true, false, false]),
            (2, [false, true, false]),
            (3, [true, true, false]),
        ] {
            let mut buffer = [0u8; 64];
            encode_header(&[&[true, true]], &[true], &[Some(symbol)], &mut buffer);
            let mut decoder = RangeDecoder::new(&buffer);
            let header = LpLayerHeader::decode(&mut decoder, 1, 2).expect("valid header");
            assert_eq!(
                header.channels[0].lbrr_flags, expected,
                "LBRR symbol {symbol}"
            );
        }
    }

    /// The same for a 60 ms frame: all seven legal 3-bit patterns.
    #[test]
    fn sixty_ms_per_frame_lbrr_flags_cover_every_pattern() {
        for symbol in 1u32..=7 {
            let mut buffer = [0u8; 64];
            encode_header(
                &[&[true, true, true]],
                &[true],
                &[Some(symbol)],
                &mut buffer,
            );
            let mut decoder = RangeDecoder::new(&buffer);
            let header = LpLayerHeader::decode(&mut decoder, 1, 3).expect("valid header");
            let expected = [
                symbol & 1 == 1,
                (symbol >> 1) & 1 == 1,
                (symbol >> 2) & 1 == 1,
            ];
            assert_eq!(
                header.channels[0].lbrr_flags, expected,
                "LBRR symbol {symbol}"
            );
        }
    }

    /// The interleaving trap: (mid VAD, mid LBRR), (side VAD, side LBRR), then mid per-frame LBRR,
    /// then side per-frame LBRR (RFC 6716 Figure 16). Distinct flag patterns per channel make a
    /// swapped grouping fail.
    #[test]
    fn stereo_60ms_flag_order_is_channel_interleaved_then_lbrr_grouped() {
        let mid_vad = [true, false, true];
        let side_vad = [false, true, true];
        let mut buffer = [0u8; 64];
        encode_header(
            &[&mid_vad, &side_vad],
            &[true, true],
            &[Some(5), Some(2)],
            &mut buffer,
        );
        let mut decoder = RangeDecoder::new(&buffer);
        let header = LpLayerHeader::decode(&mut decoder, 2, 3).expect("valid header");
        assert_eq!(header.channels[0].vad_flags, mid_vad);
        assert_eq!(header.channels[1].vad_flags, side_vad);
        assert!(header.channels[0].lbrr_flag);
        assert!(header.channels[1].lbrr_flag);
        // 5 = 0b101 -> frames 0 and 2; 2 = 0b010 -> frame 1.
        assert_eq!(header.channels[0].lbrr_flags, [true, false, true]);
        assert_eq!(header.channels[1].lbrr_flags, [false, true, false]);
    }

    /// Only the channel with LBRR data codes a per-frame symbol; the other codes none. If the decoder
    /// read a symbol for both, the side channel's flags would come out of the *next* symbol.
    #[test]
    fn stereo_only_the_lbrr_channel_consumes_a_symbol() {
        let mut buffer = [0u8; 64];
        encode_header(
            &[&[true, true], &[true, true]],
            &[false, true],
            &[None, Some(3)],
            &mut buffer,
        );
        let mut decoder = RangeDecoder::new(&buffer);
        let header = LpLayerHeader::decode(&mut decoder, 2, 2).expect("valid header");
        assert!(!header.channels[0].lbrr_flag);
        assert_eq!(header.channels[0].lbrr_flags, [false; 3]);
        assert_eq!(header.channels[1].lbrr_flags, [true, true, false]);
        assert!(header.any_lbrr());
    }

    #[test]
    fn rejects_illegal_geometry() {
        let buffer = [0u8; 8];
        let mut decoder = RangeDecoder::new(&buffer);
        assert!(LpLayerHeader::decode(&mut decoder, 0, 1).is_err());
        assert!(LpLayerHeader::decode(&mut decoder, 3, 1).is_err());
        assert!(LpLayerHeader::decode(&mut decoder, 1, 0).is_err());
        assert!(LpLayerHeader::decode(&mut decoder, 1, 4).is_err());
    }

    #[test]
    fn channel_accessor_respects_the_coded_channel_count() {
        let mut buffer = [0u8; 64];
        encode_header(&[&[true]], &[false], &[None], &mut buffer);
        let mut decoder = RangeDecoder::new(&buffer);
        let header = LpLayerHeader::decode(&mut decoder, 1, 1).expect("valid header");
        assert!(header.channel(0).is_ok());
        assert!(header.channel(1).is_err(), "side channel is not coded");
        assert!(header.channel(2).is_err());
    }

    /// A truncated or hostile payload must decode-or-error, never panic. Past the end of the buffer
    /// the range decoder yields phantom zero bytes by design, so this is about bounds and termination.
    #[test]
    fn arbitrary_and_truncated_payloads_never_panic() {
        for seed in 0u32..2000 {
            let length = (seed % 5) as usize;
            let payload: Vec<u8> = (0..length)
                .map(|k| (seed.wrapping_mul(2_654_435_761).wrapping_add(k as u32) >> 11) as u8)
                .collect();
            for channels in 1..=2 {
                for frames in 1..=MAX_FRAMES_PER_PACKET {
                    let mut decoder = RangeDecoder::new(&payload);
                    let header = LpLayerHeader::decode(&mut decoder, channels, frames)
                        .expect("geometry is legal, so decode must not error");
                    // Whatever came out, the invariants hold: no flag is set past the coded count.
                    for channel in &header.channels[..channels] {
                        assert!(channel.vad_flags[frames..].iter().all(|&flag| !flag));
                        assert!(channel.lbrr_flags[frames..].iter().all(|&flag| !flag));
                        if channel.lbrr_flag {
                            assert!(
                                channel.lbrr_flags[..frames].iter().any(|&flag| flag),
                                "a set LBRR flag must name at least one frame"
                            );
                        } else {
                            assert!(channel.lbrr_flags.iter().all(|&flag| !flag));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn decoder_stores_the_header_on_its_channel_states() {
        let mut buffer = [0u8; 64];
        encode_header(
            &[&[true, false, true], &[false, false, true]],
            &[true, false],
            &[Some(4), None],
            &mut buffer,
        );

        let mut silk = SilkDecoder::new(48_000, 2).expect("decoder");
        silk.configure(2, InternalRate::Wide16k, 60).expect("60 ms");
        let mut decoder = RangeDecoder::new(&buffer);
        let header = silk
            .decode_lp_layer_header(&mut decoder)
            .expect("valid header");

        assert_eq!(header.frames_per_packet, 3);
        let mid = silk.channel(0).expect("mid");
        assert_eq!(mid.vad_flags, [true, false, true]);
        assert!(mid.lbrr_flag);
        // 4 = 0b100 -> only the third interval carries LBRR.
        assert_eq!(mid.lbrr_flags, [false, false, true]);
        assert_eq!(mid.frames_decoded, 0);
        let side = silk.channel(1).expect("side");
        assert_eq!(side.vad_flags, [false, false, true]);
        assert!(!side.lbrr_flag);
        assert_eq!(side.lbrr_flags, [false; 3]);
    }

    /// The decoder-level wrapper must use the configured geometry, not a guess: a 10 ms mono
    /// configuration reads exactly two header bits.
    #[test]
    fn decoder_wrapper_follows_the_configured_geometry() {
        let mut buffer = [0u8; 64];
        encode_header(&[&[true]], &[false], &[None], &mut buffer);
        let mut silk = SilkDecoder::new(16_000, 1).expect("decoder");
        silk.configure(1, InternalRate::Narrow8k, 10)
            .expect("10 ms");
        let mut decoder = RangeDecoder::new(&buffer);
        let before = decoder.tell();
        let header = silk
            .decode_lp_layer_header(&mut decoder)
            .expect("valid header");
        assert_eq!(header.frames_per_packet, 1);
        assert_eq!(header.channel_count, 1);
        assert_eq!(decoder.tell() - before, 2);
    }
}
