//! The EVS frame decoder: the main loop of the reference `decoder.c` for a G.192 stream, as a
//! library type. One [`G192Frame`] in, one 20 ms frame of 16-bit PCM out, with the decoder's
//! algorithmic delay removed from the start of the stream exactly as the reference does.
//!
//! Only MODE1 (ACELP / HQ) frames decode today; a frame that needs MODE2 (TCX), AMR-WB IO or a
//! bandwidth extension this port does not have yet is refused with [`EvsError::Unsupported`] and
//! never produces audio (see [`crate::evs::dec::evs_dec::evs_dec`]).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{DEC, L_FRAME48K, MAX_FRAME_COUNTER};
use crate::evs::com::bitstream::{
    read_indices_frame, reset_indices_dec, FRAMEMODE_MISSING, FRAMEMODE_NORMAL,
};
use crate::evs::com::delay_comp::get_delay;
use crate::evs::dec::evs_dec::evs_dec;
use crate::evs::dec::init_dec::init_decoder;
use crate::evs::dec::io_dec::configure_decoder;
use crate::evs::dec::state::DecoderState;
use crate::evs::error::{EvsError, UnsupportedMode};
use crate::evs::g192::G192Frame;
use crate::evs::macros::ns2sa_fx2;
use crate::itu::basic_ops::{add, extract_l, sub};

/// `MODE1` is the first codec mode; the reference tests `codec_mode` against it.
use crate::evs::cnst::MODE1;

/// An EVS decoder for one stream at a fixed output rate (8, 16, 32 or 48 kHz).
pub struct EvsDecoder {
    st: Box<DecoderState>,
    output_frame: usize,
    /// `dec_delay`: output samples still to be dropped from the start of the stream.
    dec_delay: i16,
    /// `zero_pad`: the delay, appended as zeros at the end by [`Self::flush`].
    zero_pad: i16,
}

impl EvsDecoder {
    /// A decoder producing `output_rate_hz` (8000, 16000, 32000 or 48000) PCM, with the
    /// reference's delay compensation.
    ///
    /// # Errors
    /// [`EvsError::Malformed`] for any other output rate.
    pub fn new(output_rate_hz: u32) -> Result<Self, EvsError> {
        let mut st = Box::new(DecoderState::zeroed());
        let rate = i32::try_from(output_rate_hz).map_err(|_| {
            EvsError::Malformed("EVS output sampling rate must be 8, 16, 32 or 48 kHz")
        })?;
        configure_decoder(&mut st, rate)?;
        // output_frame = output_Fs / 50
        st.output_frame = extract_l(mult_32_16(st.output_fs, 0x0290));
        reset_indices_dec(&mut st);
        init_decoder(&mut st);
        let output_frame = usize::try_from(st.output_frame)
            .map_err(|_| EvsError::Malformed("negative output frame length"))?;
        // calculate the compensation (decoded signal aligned with original signal): the number of
        // first output samples will be reduced by this amount
        let dec_delay = ns2sa_fx2(st.output_fs, get_delay(DEC, st.output_fs));
        Ok(Self {
            st,
            output_frame,
            dec_delay,
            zero_pad: dec_delay,
        })
    }

    /// Samples one input frame decodes to before the start-of-stream delay is removed.
    #[must_use]
    pub fn frame_samples(&self) -> usize {
        self.output_frame
    }

    /// Decode one received frame into `out` (at least [`Self::frame_samples`] long) and return the
    /// number of samples written: a whole frame, fewer while the decoder delay is being dropped
    /// from the start of the stream, or none while the delay still exceeds the frame.
    ///
    /// # Errors
    /// [`EvsError::OutputTooSmall`] for a short `out`; [`EvsError::Malformed`] for a frame the
    /// reference rejects; [`EvsError::Unsupported`] for a frame that needs a part of the reference
    /// decoder this port does not run yet. After an error the decoder must be discarded.
    pub fn decode_frame(
        &mut self,
        frame: &G192Frame<'_>,
        out: &mut [i16],
    ) -> Result<usize, EvsError> {
        if out.len() < self.output_frame {
            return Err(EvsError::OutputTooSmall {
                needed: self.output_frame,
                have: out.len(),
            });
        }
        read_indices_frame(&mut self.st, frame)?;

        let mut output = [0i16; L_FRAME48K as usize];
        let st = &mut *self.st;
        // run the main decoding routine
        if sub(st.codec_mode, MODE1) == 0 {
            if st.opt_amr_wb != 0 {
                return Err(EvsError::Unsupported {
                    mode: UnsupportedMode::AmrWbIo,
                    reference_call: "amr_wb_dec_fx",
                });
            }
            evs_dec(st, &mut output, FRAMEMODE_NORMAL)?;
        } else if st.bfi == 0 {
            evs_dec(st, &mut output, FRAMEMODE_NORMAL)?;
        } else {
            // conceal
            evs_dec(st, &mut output, FRAMEMODE_MISSING)?;
        }

        // increase the counter of initialization frames
        if sub(st.ini_frame, MAX_FRAME_COUNTER) < 0 {
            st.ini_frame = add(st.ini_frame, 1);
        }

        // do final delay compensation
        let frame_len = self.output_frame;
        let delay = usize::try_from(self.dec_delay).unwrap_or(0);
        if delay == 0 {
            out[..frame_len].copy_from_slice(&output[..frame_len]);
            Ok(frame_len)
        } else if delay <= frame_len {
            let kept = frame_len - delay;
            out[..kept].copy_from_slice(&output[delay..frame_len]);
            self.dec_delay = 0;
            Ok(kept)
        } else {
            self.dec_delay = sub(self.dec_delay, extract_l(frame_len as i32));
            Ok(0)
        }
    }

    /// The zeros the reference appends at the end of the stream so the output is as long as the
    /// input; writes them to `out` and returns how many.
    ///
    /// # Errors
    /// [`EvsError::OutputTooSmall`] when `out` cannot hold them.
    pub fn flush(&mut self, out: &mut [i16]) -> Result<usize, EvsError> {
        let count = usize::try_from(self.zero_pad).unwrap_or(0);
        let have = out.len();
        let slot = out.get_mut(..count).ok_or(EvsError::OutputTooSmall {
            needed: count,
            have,
        })?;
        slot.fill(0);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::g192::G192Reader;

    /// A G.192 frame of `bits` zero bits (sync word good, then the length, then the bit words).
    fn g192_frame(bits: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x6B21u16.to_le_bytes());
        bytes.extend_from_slice(&(bits as u16).to_le_bytes());
        for _ in 0..bits {
            bytes.extend_from_slice(&0x007Fu16.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn refuses_an_output_rate_the_reference_rejects() {
        for rate in [0, 12_000, 44_100, 96_000] {
            assert!(matches!(EvsDecoder::new(rate), Err(EvsError::Malformed(_))));
        }
    }

    #[test]
    fn frame_length_and_delay_follow_the_output_rate() {
        for (rate, samples) in [(8000, 160), (16000, 320), (32000, 640), (48000, 960)] {
            let decoder = EvsDecoder::new(rate).unwrap();
            assert_eq!(decoder.frame_samples(), samples);
        }
    }

    #[test]
    fn a_short_output_buffer_is_refused() {
        let mut decoder = EvsDecoder::new(8000).unwrap();
        let bytes = g192_frame(160);
        let frame = G192Reader::new(&bytes).next().unwrap().unwrap();
        let mut out = [0i16; 10];
        assert_eq!(
            decoder.decode_frame(&frame, &mut out),
            Err(EvsError::OutputTooSmall {
                needed: 160,
                have: 10
            })
        );
    }

    #[test]
    fn the_first_frames_are_trimmed_by_the_decoder_delay() {
        let mut decoder = EvsDecoder::new(8000).unwrap();
        let bytes = g192_frame(160); // 8 kbit/s
        let frame = G192Reader::new(&bytes).next().unwrap().unwrap();
        let mut out = [0i16; 160];
        let written = decoder.decode_frame(&frame, &mut out).unwrap();
        assert_eq!(written, 160 - usize::try_from(decoder.zero_pad).unwrap());
        let mut tail = [0i16; 160];
        assert_eq!(
            decoder.flush(&mut tail).unwrap(),
            usize::try_from(decoder.zero_pad).unwrap()
        );
        assert!(matches!(
            decoder.flush(&mut []),
            Err(EvsError::OutputTooSmall { .. })
        ));
    }
}
