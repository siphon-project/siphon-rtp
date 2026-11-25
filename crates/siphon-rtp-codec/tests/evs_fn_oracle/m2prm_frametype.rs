//! `lib_dec/dec_acelp_tcx_main.c` `decode_frame_type` against `fn_m2prm_frametype`, on the whole
//! decoder state: the frame header read and the rate-change reconfiguration (core, CLDFB banks,
//! FD-CNG).

use siphon_rtp_codec::evs::cnst::{MODE1, MODE2, SID_FRAME, ZERO_FRAME};
use siphon_rtp_codec::evs::dec::dec_acelp_tcx_main::decode_frame_type;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::rom::FRAMESIZECONFIG;

use crate::common::{corpus_sized, Case};
use crate::state_case::state_after;
use crate::state_dump;

/// The decoder "before" state: a state load does not restore the ROM tables the decoder selects
/// from configuration fields (the TCX window slopes, the IGF coder's tables, the CLDFB prototype
/// and twiddles), so the decoder is first brought up the way the oracle did, by decoding the first
/// frame's header of a stream, and the oracle's state is loaded over it.
fn prepared_before(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("output_fs");
    st.output_frame = case.i16("output_frame");
    init_decoder(&mut st);

    let (rate, bandwidth, rf) = (
        case.i32("first_rate"),
        case.i16("first_bw"),
        case.i16("first_rf"),
    );
    let index = FRAMESIZECONFIG
        .iter()
        .position(|config| i32::from(config.frame_bits) == rate / 50)
        .unwrap();
    st.last_codec_mode = MODE1;
    st.mdct_sw = MODE2;
    st.rf_flag = rf;
    st.bwidth = if rf != 0 {
        bandwidth - i16::from(FRAMESIZECONFIG[index].bandwidth_min)
    } else {
        bandwidth
    };
    st.last_bwidth = bandwidth;
    st.rf_flag_last = rf;
    st.nb_subfr = 4;
    st.ini_frame = 0;
    st.last_total_brate = 0;
    for (slot, &bit) in st
        .bit_stream
        .iter_mut()
        .zip(case.inputs.get("first_bits").unwrap())
    {
        *slot = bit as u16;
    }
    st.next_bit_pos = 0;
    st.total_num_bits = 64;
    st.total_brate = rate;
    decode_frame_type(&mut st);

    state_dump::load(&mut st, &case.inputs, "in.");
    for (slot, &bit) in st
        .bit_stream
        .iter_mut()
        .zip(case.inputs.get("bits").unwrap())
    {
        *slot = bit as u16;
    }
    st
}

#[test]
fn decode_frame_type_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized("m2prm_frametype", "decode_frame_type", 400) else {
        return;
    };
    let (mut switched, mut sid, mut zero, mut flagged) = (0, 0, 0, 0);
    for (index, case) in cases.iter().enumerate() {
        let mut st = prepared_before(case);
        decode_frame_type(&mut st);
        switched += usize::from(st.rate_switching_init != 0);
        sid += usize::from(st.m_frame_type == SID_FRAME);
        zero += usize::from(st.m_frame_type == ZERO_FRAME);
        flagged += usize::from(st.ber_detect != 0);
        let context = format!("decode_frame_type case {index}");
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
    assert!(
        switched > 100 && sid > 40 && zero > 10 && flagged > 20,
        "switched {switched}, sid {sid}, zero {zero}, flagged {flagged}"
    );
}
