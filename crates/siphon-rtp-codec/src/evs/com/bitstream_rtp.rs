//! Taking one frame received in an RTP payload into the decoder: the RTP half of the reference's
//! `lib_com/bitstream_fx.c`, `read_indices_mime` / `read_indices_from_djb_fx` with their
//! `read_indices_mime_handle_dtx` and `read_indices_mime_handle_sti_and_all_zero_bits`.
//!
//! [`super::bitstream::read_indices`] is the G.192 file reader and has its own DTX handler, which
//! reads a lost frame from the file's length word. An RTP frame carries the sender's own account
//! instead: the `Q` bit of an AMR-WB IO frame, the frame types SPEECH_LOST and NO_DATA, and the STI
//! bit of an AMR-WB IO SID that tells SID_FIRST from SID_UPDATE (TS 26.445 A.2.2.1.3). The two
//! handlers settle on the same decoder state for the same situation, but they get to it from
//! different information, so each is ported as it is.

use super::bitstream::{decoder_select_codec, mdct_switching_dec, reset_indices_dec};
use crate::evs::cnst::{MAX_BITS_PER_FRAME, SID_1K75, SID_2K40};
use crate::evs::dec::state::DecoderState;
use crate::CodecError;

/// `ACELP_12k65`: the rate the decoder starts up in when the first frame it is given is lost.
const ACELP_12K65: i32 = 12650;

/// The AMR-WB IO bit rate of each frame type index (`AMRWB_IOmode2rate`, `lib_com/mime.h`).
const AMR_WB_IO_RATE: [i32; 16] = [
    6600, 8850, 12650, 14250, 15850, 18250, 19850, 23050, 23850, 1750, -1, -1, -1, -1, 0, 0,
];

/// One frame received in an RTP payload, as the decoder is given it.
#[derive(Debug, Clone, Copy)]
pub struct ReceivedFrame<'a> {
    /// The table of contents named the AMR-WB IO mode (`isAMRWB_IOmode`).
    pub amr_wb_io: bool,
    /// The table of contents' 4-bit frame type (`core_mode`).
    pub frame_type_index: u8,
    /// The `Q` bit: `false` for a frame marked damaged.
    pub quality_ok: bool,
    /// The frame type is SPEECH_LOST.
    pub speech_lost: bool,
    /// The frame type is NO_DATA.
    pub no_data: bool,
    /// The STI bit of an AMR-WB IO SID: `Some(false)` SID_FIRST, `Some(true)` SID_UPDATE.
    pub sid_update: Option<bool>,
    /// The speech bits, one per element (0 or 1), in the order the decoder reads them. Empty for
    /// SPEECH_LOST and NO_DATA.
    pub bits: &'a [u8],
}

/// `read_indices_mime_handle_sti_and_all_zero_bits`: the STI bit decides what an AMR-WB IO SID is,
/// and an all-zero SID_UPDATE (a valid filter with an extreme gain, typically a bit error or a
/// gateway filling in) is marked bad.
fn handle_sti_and_all_zero_bits(st: &mut DecoderState, total_brate: &mut i32, sid_update: bool) {
    let sid_bits = &st.bit_stream[..35];
    if sid_update {
        // sid_update received: all zeros are suspect
        if sid_bits.iter().all(|&bit| bit == 0) {
            // eventually becomes SID_UPD_BAD
            st.bfi = 1;
        }
    } else {
        // SID_FIRST is a good frame with no bits; any single 1 among the 35 that must be zero
        // marks it bad
        let any_set = sid_bits.iter().any(|&bit| bit != 0);
        *total_brate = 0;
        st.bfi |= i16::from(any_set);
    }
}

/// `read_indices_mime_handle_dtx`: keep the CNG state, `bfi` and the bit rate right for synthesis
/// through DTX and frame erasure, returning the frame's effective bit rate.
fn handle_dtx(
    st: &mut DecoderState,
    frame: &ReceivedFrame<'_>,
    mut total_brate: i32,
    sti: Option<bool>,
) -> i32 {
    let sid_2k40 = i32::from(SID_2K40);
    let sid_1k75 = i32::from(SID_1K75);
    let mut no_data = frame.no_data;
    let mut curr_ft_good_sp = false;
    let mut speech_bad = false;
    let mut sid_upd_bad = false;
    let mut sid_update = false;
    let mut amr_wb_sid_first = false;

    // keep CNG, bfi and total_brate updated for proper synthesis in DTX and FER
    if total_brate > sid_2k40 && st.bfi != 1 {
        curr_ft_good_sp = true;
    }

    // handle a q_bit and lost_sp clash, assume the worst case: SPEECH_LOST overrides a good q_bit
    if frame.speech_lost {
        curr_ft_good_sp = false;
        st.bfi = 1;
    }

    // SID_UPDATE check
    if total_brate == sid_1k75 || total_brate == sid_2k40 {
        if st.bfi == 0 {
            sid_update = true;
        } else {
            // may happen in saving from e.g. a CS-connection
            sid_upd_bad = true;
        }
    }

    // SID_FIRST of the AMR-WB IO mode (STI = 0, no bits left)
    if frame.amr_wb_io && total_brate == 0 && sti == Some(false) {
        if st.bfi != 0 {
            // corrupt SID_FIRST, signalled as a bad SID
            sid_upd_bad = true;
        } else {
            amr_wb_sid_first = true;
        }
    }

    if sid_upd_bad
        && ((frame.amr_wb_io && st.opt_amr_wb == 0) || (!frame.amr_wb_io && st.opt_amr_wb == 1))
    {
        // do not allow a normal start of CNG synthesis if this SID (with BER or FER) is a switch
        // to or from the AMR-WB IO mode: revert this detection, bfi stays 1
        sid_upd_bad = false;
        total_brate = 0;
        no_data = true;
    }

    if total_brate > sid_2k40 && st.bfi == 1 {
        // initial assumption, the CNG synthesis state decides what to actually do
        speech_bad = true;
    }

    // update the CNG synthesis state: the decoder can only enter CNG synthesis on a CNG frame type
    if st.cng != 0 {
        // only a good speech frame makes the decoder leave CNG synthesis
        if curr_ft_good_sp {
            st.cng = 0;
        }
    } else if amr_wb_sid_first || sid_update || sid_upd_bad {
        st.cng = 1;
    }

    // in speech synthesis a NO_DATA frame is treated as a lost one: speech PLC becomes active
    if st.cng == 0 && no_data {
        st.bfi = 1;
    }

    // in CNG, a bad speech frame (and a bad SID) keeps the decoder in CNG synthesis
    if (st.cng != 0 && (speech_bad || frame.speech_lost || no_data)) || sid_upd_bad {
        // mark as good so speech PLC is not started
        st.bfi = 0;
        total_brate = 0;
    }

    // the AMR-WB ToC rate information at start-up: the decoder starts in a selected AMR-WB mode
    if st.bfi == 1 && st.ini_frame == 0 && frame.amr_wb_io {
        let mut init_rate = total_brate;
        if frame.speech_lost || no_data {
            init_rate = ACELP_12K65;
        } else if speech_bad {
            init_rate = AMR_WB_IO_RATE
                .get(usize::from(frame.frame_type_index))
                .copied()
                .unwrap_or(total_brate);
        }
        st.total_brate = init_rate;
        st.core_brate = init_rate;
    }

    total_brate
}

/// Take `frame`, received in an RTP payload, into the decoder state: the counterpart of
/// [`super::bitstream::read_indices`] for the RTP payload format.
///
/// # Errors
/// [`CodecError::Malformed`] for more bits than `MAX_BITS_PER_FRAME`. The state is left untouched.
pub fn read_indices_received(
    st: &mut DecoderState,
    frame: &ReceivedFrame<'_>,
) -> Result<(), CodecError> {
    let num_bits = frame.bits.len();
    if num_bits > MAX_BITS_PER_FRAME as usize {
        return Err(CodecError::Malformed("too large EVS frame"));
    }
    // fits: num_bits <= 2560
    let mut total_brate = num_bits as i32 * 50;

    st.bfi = 0;
    st.ber_detect = 0;
    st.mdct_sw_enable = 0;
    st.mdct_sw = 0;
    reset_indices_dec(st);
    st.bfi = i16::from(!frame.quality_ok);
    st.total_num_bits = num_bits as i16;

    // unpack speech data
    for (slot, &bit) in st.bit_stream.iter_mut().zip(frame.bits) {
        *slot = u16::from(bit != 0);
    }

    // unpack auxiliary bits: an AMR-WB IO SID is followed by the STI bit (A.2.2.1.3)
    let mut sti = None;
    if frame.amr_wb_io && total_brate == i32::from(SID_1K75) {
        let sid_update = frame.sid_update.unwrap_or(true);
        sti = Some(sid_update);
        handle_sti_and_all_zero_bits(st, &mut total_brate, sid_update);
    }

    // add two zero bytes for the arithmetic coder flush
    for slot in st.bit_stream.iter_mut().skip(num_bits).take(2 * 8) {
        *slot = 0;
    }

    total_brate = handle_dtx(st, frame, total_brate, sti);

    if st.bfi != 1 {
        // select MODE1 or MODE2
        decoder_select_codec(st, total_brate, st.bit_stream[0] == 0);
        // a change of the total bitrate should not be known to the decoder if the received frame
        // was truly lost
        st.total_brate = total_brate;
        mdct_switching_dec(st);
    }
    Ok(())
}
