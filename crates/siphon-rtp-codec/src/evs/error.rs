//! Errors of the EVS decoder.

use crate::CodecError;

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
