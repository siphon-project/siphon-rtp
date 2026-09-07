//! G.729 — 8 kbit/s speech coding using conjugate-structure algebraic-code-excited linear
//! prediction (CS-ACELP), ITU-T G.729 with Annex A and Annex B.
//!
//! Ported from the ITU-T G.729 Release 3 fixed-point reference C, function by function, and
//! validated bit-exact against the official test vectors that ship with it: decoding each `*.bit`
//! must reproduce the corresponding `*.pst` byte for byte. `reference/g729/README.md` records where
//! that material comes from and why a round trip is not accepted in its place.
//!
//! The frame is 10 ms — 80 samples at 8 kHz, carried in 80 bits, so 10 octets — split into two
//! 40-sample subframes (RFC 3551 §4.5.6 assigns it static payload type 18). Its arithmetic is the
//! shared ITU fixed-point substrate in [`crate::itu`]; only the routines whose Q formats differ
//! between codec lineages are restated here.
//!
//! Gated behind the off-by-default `g729` Cargo feature, which gates **transcoding** only:
//! relaying G.729 never executes a codec and never reaches this module. See
//! `docs/codec-licensing.md`.

pub mod bitstream;
pub mod decoder;
pub mod dspfunc;
pub mod excitation;
pub mod filter;
pub mod lpcfunc;
pub mod lspdec;
pub mod overflow;
pub mod postfilter;
pub mod postproc;
pub mod tables;

use bitstream::{FrameParameters, FRAME_SAMPLES, SUBFRAME_SAMPLES};
use filter::ORDER;

/// A complete G.729 decoder: the frame loop, the adaptive postfilter and the output
/// post-processing, in the order `dec_ld8k` / `Post` / `Post_Process` run in the reference's own
/// `decoder.c`.
///
/// One instance decodes one stream; all of its state is per-stream and none of it is shared, so a
/// leg owns its decoder outright.
#[derive(Debug, Clone)]
pub struct G729Decoder {
    core: decoder::Decoder,
    postfilter: postfilter::PostFilter,
    postprocessor: postproc::PostProcessor,
    /// Synthesis history: the previous frame's last `ORDER` samples, which the postfilter's inverse
    /// filter reaches back into, followed by the frame being decoded.
    synthesis: [i16; ORDER + FRAME_SAMPLES],
    /// The postfilter's voicing decision from the previous frame, which concealment consults.
    voicing: i16,
}

impl Default for G729Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl G729Decoder {
    /// A decoder in its reset state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            core: decoder::Decoder::new(),
            postfilter: postfilter::PostFilter::new(),
            postprocessor: postproc::PostProcessor::new(),
            synthesis: [0; ORDER + FRAME_SAMPLES],
            // The reference starts its decoder loop with the leg treated as voiced.
            voicing: 60,
        }
    }

    /// Decode one 10-octet frame into 80 samples.
    ///
    /// # Errors
    ///
    /// [`crate::CodecError::Malformed`] when the payload is not exactly ten octets long.
    pub fn decode(&mut self, frame: &[u8]) -> Result<[i16; FRAME_SAMPLES], crate::CodecError> {
        let parameters = bitstream::unpack(frame)?;
        Ok(self.decode_parameters(Some(&parameters)))
    }

    /// Conceal one lost frame, producing 80 samples from the decoder's own state.
    pub fn conceal(&mut self) -> [i16; FRAME_SAMPLES] {
        self.decode_parameters(None)
    }

    fn decode_parameters(&mut self, parameters: Option<&FrameParameters>) -> [i16; FRAME_SAMPLES] {
        let (synthesised, filters, first_lag) = self.core.decode_frame(parameters, self.voicing);
        self.synthesis[ORDER..].copy_from_slice(&synthesised);

        // Both subframes are postfiltered against the *first* subframe's pitch lag: the harmonic
        // search re-derives its own delay anyway, and the reference hands it one starting point for
        // the whole frame rather than one per subframe.
        let mut postfiltered = [0_i16; FRAME_SAMPLES];
        let mut voicing = 0;
        for (subframe, filter) in filters.iter().enumerate() {
            let start = subframe * SUBFRAME_SAMPLES;
            let subframe_voicing = self.postfilter.process(
                first_lag,
                &self.synthesis,
                ORDER + start,
                filter,
                &mut postfiltered[start..start + SUBFRAME_SAMPLES],
            );
            if subframe_voicing != 0 {
                voicing = subframe_voicing;
            }
        }
        self.voicing = voicing;

        // Carry this frame's tail into the next frame's history.
        self.synthesis.copy_within(FRAME_SAMPLES.., 0);

        self.postprocessor.process(&mut postfiltered);
        postfiltered
    }
}
