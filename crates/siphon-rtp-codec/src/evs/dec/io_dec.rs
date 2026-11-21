//! Decoder configuration from the reference's command line (TS 26.442 `lib_dec/io_dec_fx.c`).
//!
//! `io_ini_dec_fx` parses `EVS_dec [options] <kHz> in.COD out.OUT`, opens the files, pre-reads the
//! first G.192 frame and prints a banner. Only the decoder-state configuration it performs for the
//! plain G.192 decoding mode every conformance case uses (TS 26.444 `Readme_EVS_dec.txt`: the
//! output rate and nothing else) is ported here: file handling, the MIME / VoIP / JBM options and
//! `bit_rate_to_string` (which only formats the bit rate for printing) are not. The reference's
//! pre-read of the first frame (`read_indices_fx(st, f, 1)`) is the caller's, through
//! `evs::com::bitstream::read_indices`.

use crate::evs::dec::state::DecoderState;
use crate::CodecError;

/// `G192`, the first enumerator of the bitstream-format `enum` in `cnst_fx.h` (an `enum`, so not
/// among the generated `#define` constants).
pub const G192: i16 = 0;

/// The decoder-state part of `io_ini_dec_fx` for a G.192 bitstream decoded to `output_fs_hz`:
/// AMR-WB IO and VoIP off, G.192 format, no RFC 4867 storage format.
///
/// # Errors
/// [`CodecError::Unsupported`] for an output rate other than 8, 16, 32 or 48 kHz (where the
/// reference prints its usage and exits).
pub fn configure_decoder(st: &mut DecoderState, output_fs_hz: i32) -> Result<(), CodecError> {
    // Output sampling frequency
    if !matches!(output_fs_hz, 8000 | 16000 | 32000 | 48000) {
        return Err(CodecError::Unsupported(
            "EVS output sampling rate must be 8, 16, 32 or 48 kHz",
        ));
    }

    // Initialization
    st.opt_amr_wb = 0;
    st.opt_voip = 0;
    st.bitstreamformat = G192;
    st.amrwb_rfc4867_flag = -1;
    st.output_fs = output_fs_hz;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configures_every_output_rate_the_reference_accepts() {
        for rate in [8000, 16000, 32000, 48000] {
            let mut st = Box::new(DecoderState::zeroed());
            st.opt_amr_wb = 1;
            st.opt_voip = 1;
            st.bitstreamformat = 3;
            assert!(configure_decoder(&mut st, rate).is_ok());
            assert_eq!(st.output_fs, rate);
            assert_eq!(st.opt_amr_wb, 0);
            assert_eq!(st.opt_voip, 0);
            assert_eq!(st.bitstreamformat, G192);
            assert_eq!(st.amrwb_rfc4867_flag, -1);
        }
    }

    #[test]
    fn refuses_a_rate_the_reference_rejects_and_leaves_the_state_alone() {
        for rate in [0, 12000, 24000, 44100, 96000, -8000] {
            let mut st = Box::new(DecoderState::zeroed());
            st.output_fs = 16000;
            assert!(matches!(
                configure_decoder(&mut st, rate),
                Err(CodecError::Unsupported(_))
            ));
            assert_eq!(st.output_fs, 16000);
        }
    }
}
