//! `lib_dec/dec_prm.c` (`dec_prm` and its static `dec_prm_hm`) and `get_tbe_bits_fx` against
//! `fn_m2prm_dec_prm`. `dec_prm` is compared on the parameter vectors, the coder type, the bits
//! read and the whole decoder state, over random streams at every MODE2 rate and bandwidth.

use siphon_rtp_codec::evs::cnst::MODE1;
use siphon_rtp_codec::evs::com::swb_tbe_com::get_tbe_bits;
use siphon_rtp_codec::evs::dec::core_dec_switch::mode_switch_decoder_lpd;
use siphon_rtp_codec::evs::dec::dec_prm::dec_prm;
use siphon_rtp_codec::evs::dec::init_dec::init_decoder;
use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::rom::FRAMESIZECONFIG;

use crate::common::{corpus, corpus_sized, Case};
use crate::state_case::state_after;
use crate::state_dump;

const MODULE: &str = "m2prm_dec_prm";

/// Compare one output; a mismatch names the case by its configuration (the stream is too long to
/// print) and the first differing values.
fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if rust != reference {
        let summary = ["rate", "bw", "rf", "coder_type", "total_nbbits", "l_frame"]
            .iter()
            .map(|key| format!("{key}={:?}", case.inputs.get(*key).map(|v| v[0])))
            .collect::<Vec<_>>()
            .join(" ");
        panic!("{name} differs ({summary}): rust {rust:.300?} reference {reference:.300?}");
    }
}

fn check_vector(case: &Case, name: &str, rust: &[i16], reference: &[i16]) {
    if rust != reference {
        let first = rust
            .iter()
            .zip(reference)
            .position(|(a, b)| a != b)
            .unwrap_or(rust.len().min(reference.len()));
        let window = |values: &[i16]| {
            values[first.min(values.len())..(first + 8).min(values.len())].to_vec()
        };
        let summary = ["rate", "bw", "rf", "coder_type", "total_nbbits", "l_frame"]
            .iter()
            .map(|key| format!("{key}={:?}", case.inputs.get(*key).map(|v| v[0])))
            .collect::<Vec<_>>()
            .join(" ");
        panic!(
            "{name} differs at [{first}] ({summary}): rust {:?} reference {:?}",
            window(rust),
            window(reference)
        );
    }
}

/// The decoder "before" state. A state load does not restore the ROM tables the decoder selects
/// from configuration fields (TCX windows, IGF coder tables, TNS parameters), so the decoder is
/// first brought to the oracle's running configuration the way the oracle did (a first
/// `mode_switch_decoder_LPD`), and the oracle's state is loaded over it.
fn prepared_before(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    st.output_fs = case.i32("output_fs");
    st.output_frame = case.i16("output_frame");
    init_decoder(&mut st);

    let (rate, bandwidth, rf) = (case.i32("rate"), case.i16("bw"), case.i16("rf"));
    let index = FRAMESIZECONFIG
        .iter()
        .position(|config| i32::from(config.frame_bits) == rate / 50)
        .unwrap();
    st.total_brate = rate;
    st.bwidth = bandwidth;
    st.last_bwidth = bandwidth;
    st.rf_flag = rf;
    st.ini_frame = 0;
    st.last_codec_mode = MODE1;
    st.nb_subfr = 4;
    mode_switch_decoder_lpd(&mut st, bandwidth, rate, index as i16);

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
fn get_tbe_bits_matches_the_reference() {
    let Some(cases) = corpus(MODULE, "get_tbe_bits") else {
        return;
    };
    for case in &cases {
        let bits = get_tbe_bits(case.i32("rate"), case.i16("bandwidth"), case.i16("rf"));
        check(case, "r", &bits, &case.out_i16("r"));
    }
}

#[test]
fn dec_prm_matches_the_reference_on_the_whole_state() {
    let Some(cases) = corpus_sized(MODULE, "dec_prm", 500) else {
        return;
    };
    let (mut acelp, mut tcx20, mut tcx10, mut partial, mut flagged) = (0, 0, 0, 0, 0);
    for (index, case) in cases.iter().enumerate() {
        let mut st = prepared_before(case);
        let mut coder_type = case.i16("coder_type");
        let mut bits_read = 0i16;
        let mut param = vec![0x5a5a_i16; 729 * 2 + 136];
        let (prm, param_lpc) = param.split_at_mut(729 * 2);
        dec_prm(
            &mut coder_type,
            prm,
            param_lpc,
            case.i16("total_nbbits"),
            &mut st,
            case.i16("l_frame"),
            &mut bits_read,
        );
        match (st.use_partial_copy, st.core) {
            (0, 0) => acelp += 1,
            (0, 1) => tcx20 += 1,
            (0, 2) => tcx10 += 1,
            _ => partial += 1,
        }
        flagged += usize::from(st.ber_detect != 0);
        let context = format!(
            "dec_prm case {index}: rate {} bw {} rf {} core {} tcxonly {} partial {} coder {} sr_core {} lpcq {} midlpc {} igf {} gplc {}",
            case.i32("rate"),
            case.i16("bw"),
            case.i16("rf"),
            st.core,
            st.tcxonly,
            st.use_partial_copy,
            coder_type,
            st.sr_core,
            st.lpc_quantization,
            st.acelp_cfg.mid_lpc,
            st.igf,
            st.enable_gplc
        );
        state_dump::check(&mut st, &state_after(case), "st.", &context);
        check_vector(case, "param", &param, &case.out_i16s("param"));
        check(
            case,
            "coder_type",
            &coder_type,
            &case.out_i16("coder_type_out"),
        );
        check(case, "bits_read", &bits_read, &case.out_i16("bits_read"));
    }
    assert!(
        acelp > 40 && tcx20 > 40 && tcx10 > 10 && partial > 10 && flagged > 20 && flagged < 230,
        "acelp {acelp}, tcx20 {tcx20}, tcx10 {tcx10}, partial {partial}, flagged {flagged}"
    );
}
