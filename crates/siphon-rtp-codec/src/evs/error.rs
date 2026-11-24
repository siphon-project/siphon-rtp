//! Errors of the EVS decoder.

use crate::CodecError;

/// A part of the reference decoder this port does not run yet. A frame that needs one is refused
/// with [`EvsError::Unsupported`]: it never produces audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedMode {
    /// MODE2 (TCX / MDCT-based LPD core and its concealment; `dec_acelp_tcx_frame`).
    Mode2,
    /// AMR-WB interoperable mode (`amr_wb_dec_fx`) and the switch from it (`updt_IO_switch_dec_fx`).
    AmrWbIo,
    /// The channel-aware (RF) partial copy.
    ChannelAware,
}

impl core::fmt::Display for UnsupportedMode {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Mode2 => "MODE2 (TCX core)",
            Self::AmrWbIo => "AMR-WB IO",
            Self::ChannelAware => "channel-aware partial copy",
        })
    }
}

/// Why an EVS frame could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvsError {
    /// The frame is not a legal EVS frame (or the output rate is not 8, 16, 32 or 48 kHz).
    #[error("malformed EVS frame: {0}")]
    Malformed(&'static str),
    /// The caller-provided output buffer is smaller than one frame.
    #[error("output buffer too small: need {needed} samples, have {have}")]
    OutputTooSmall {
        /// Samples one frame decodes to.
        needed: usize,
        /// Samples the buffer holds.
        have: usize,
    },
    /// The frame needs a part of the reference decoder that is not ported yet; `reference_call` is
    /// the C call the port stops at.
    #[error("EVS {mode} is not supported yet (reference call {reference_call})")]
    Unsupported {
        /// What the frame needs.
        mode: UnsupportedMode,
        /// The reference function the port stands in for.
        reference_call: &'static str,
    },
}

impl From<CodecError> for EvsError {
    fn from(error: CodecError) -> Self {
        match error {
            CodecError::OutputTooSmall { needed, have } => Self::OutputTooSmall { needed, have },
            CodecError::Malformed(reason) | CodecError::Unsupported(reason) => {
                Self::Malformed(reason)
            }
            CodecError::BadFrameSize { .. } => Self::Malformed("bad frame size"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_names_the_mode_and_the_reference_call() {
        let error = EvsError::Unsupported {
            mode: UnsupportedMode::Mode2,
            reference_call: "dec_acelp_tcx_frame",
        };
        assert_eq!(
            error.to_string(),
            "EVS MODE2 (TCX core) is not supported yet (reference call dec_acelp_tcx_frame)"
        );
    }

    #[test]
    fn converts_codec_errors() {
        assert_eq!(
            EvsError::from(CodecError::OutputTooSmall { needed: 2, have: 1 }),
            EvsError::OutputTooSmall { needed: 2, have: 1 }
        );
        assert_eq!(
            EvsError::from(CodecError::Malformed("x")),
            EvsError::Malformed("x")
        );
    }
}
