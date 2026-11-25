//! The decoder the MODE2 concealment oracles start from: built as `m2conceal_state.h` builds it
//! (`init_decoder_fx`, then `open_decoder_LPD` at the case's rate and bandwidth, which also
//! installs the TCX window ROM pointers the state dump does not carry), then loaded with the
//! "before" state of the case.

use siphon_rtp_codec::evs::dec::core_dec_init::open_decoder_lpd;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::Case;
use crate::state_dump;

const MODE2: i16 = 2;

pub fn lpd_decoder_before(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("output_fs");
    st.output_frame = case.i16("output_frame");
    init_decoder(&mut st);
    st.codec_mode = MODE2;
    st.bwidth = case.i16("bandwidth");
    st.total_brate = case.i32("bitrate");
    st.core_brate = case.i32("bitrate");
    open_decoder_lpd(&mut st, case.i32("bitrate"), case.i16("bandwidth"));
    state_dump::load(&mut st, &case.inputs, "in.");
    st
}
