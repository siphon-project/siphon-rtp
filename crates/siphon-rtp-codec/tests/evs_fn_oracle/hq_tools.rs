//! The small helpers of `lib_com/hq_tools_fx.c` against `fn_hq_tools`, on the layouts, classes and
//! rates `hq_hr_dec_fx` runs them with.

use siphon_rtp_codec::evs::com::hq_tools::{
    enforce_zero_for_min_envelope, get_nor_delta_hf, hq_fold_bwe, hvq_concat_bands,
    map_hq_generic_fenv_norm,
};
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch};

fn report(messages: impl IntoIterator<Item = Option<String>>) {
    if let Some(message) = messages.into_iter().flatten().next() {
        panic!("{message}");
    }
}

#[test]
fn hvq_concat_bands_matches_the_reference() {
    let Some(cases) = corpus("hq_tools", "hvq_concat_bands") else {
        return;
    };
    for case in &cases {
        let (mut start, mut width, mut end) = ([-7i16; 16], [-7i16; 16], [-7i16; 16]);
        hvq_concat_bands(
            case.i16("pvq_bands"),
            &case.i16s("sel"),
            case.i16("n_sel"),
            &mut start,
            &mut width,
            &mut end,
        );
        report([
            mismatch(case, "start", &start.to_vec(), &case.out_i16s("start")),
            mismatch(case, "width", &width.to_vec(), &case.out_i16s("width")),
            mismatch(case, "end", &end.to_vec(), &case.out_i16s("end")),
        ]);
    }
}

#[test]
fn hq_fold_bwe_matches_the_reference() {
    let Some(cases) = corpus("hq_tools", "hq_fold_bwe") else {
        return;
    };
    for case in &cases {
        let mut coeff = case.i16s("coeff");
        hq_fold_bwe(
            case.i16("last_sfm"),
            &case.i16s("sfm_end"),
            case.i16("num_sfm"),
            &mut coeff,
        );
        report([mismatch(case, "coeff", &coeff, &case.out_i16s("coeff"))]);
    }
}

#[test]
fn enforce_zero_for_min_envelope_matches_the_reference() {
    let Some(cases) = corpus("hq_tools", "enforce_zero_for_min_envelope") else {
        return;
    };
    for case in &cases {
        let mut coefsq = case.i32s("coefsq");
        enforce_zero_for_min_envelope(
            case.i16("hqswb_clas"),
            &case.i16s("ynrm"),
            &mut coefsq,
            case.i16("nb_sfm"),
            &case.i16s("sfm_start"),
            &case.i16s("sfm_end"),
        );
        report([mismatch(case, "coefsq", &coefsq, &case.out_i32s("coefsq"))]);
    }
}

#[test]
fn map_hq_generic_fenv_norm_matches_the_reference() {
    let Some(cases) = corpus("hq_tools", "map_hq_generic_fenv_norm") else {
        return;
    };
    for case in &cases {
        let mut ynrm = case.i16s("ynrm");
        let mut normqlg2 = case.i16s("normqlg2");
        map_hq_generic_fenv_norm(
            case.i16("hqswb_clas"),
            &case.i16s("fenv"),
            &mut ynrm,
            &mut normqlg2,
            case.i16("num_env_bands"),
            case.i16("nb_sfm"),
            case.i16("hq_generic_offset"),
        );
        report([
            mismatch(case, "ynrm", &ynrm, &case.out_i16s("ynrm")),
            mismatch(case, "normqlg2", &normqlg2, &case.out_i16s("normqlg2")),
        ]);
    }
}

#[test]
fn get_nor_delta_hf_matches_the_reference() {
    let Some(cases) = corpus("hq_tools", "get_nor_delta_hf") else {
        return;
    };
    let mut bit_errors = 0;
    for case in &cases {
        // a case the reference did not return from (update_rsubband_fx spinning) is printed as skip
        if case.outputs.contains_key("skip") {
            continue;
        }
        let mut st = Box::new(DecoderState::zeroed());
        let bits = case.i16s("bits");
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        st.next_bit_pos = case.i16("next_bit_pos");
        st.codec_mode = 1;
        let mut ynrm = case.i16s("ynrm");
        let mut rsubband = case.i16s("rsubband");
        let used = get_nor_delta_hf(
            &mut st,
            &mut ynrm,
            &mut rsubband,
            case.i16("num_env_bands"),
            case.i16("nb_sfm"),
            case.i16("core_sfm"),
        );
        bit_errors += i32::from(st.ber_detect != 0);
        report([
            mismatch(case, "bits", &used, &case.out_i16("bits")),
            mismatch(case, "ynrm", &ynrm, &case.out_i16s("ynrm")),
            mismatch(case, "rsubband", &rsubband, &case.out_i16s("rsubband")),
            mismatch(
                case,
                "next_bit_pos",
                &st.next_bit_pos,
                &case.out_i16("next_bit_pos"),
            ),
            mismatch(
                case,
                "ber_detect",
                &st.ber_detect,
                &case.out_i16("ber_detect"),
            ),
        ]);
    }
    assert!(bit_errors > 10, "bit errors {bit_errors}");
}
