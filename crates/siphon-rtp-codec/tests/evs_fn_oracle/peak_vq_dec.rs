//! `lib_dec/peak_vq_dec_fx.c` (`hvq_dec_fx`, `peak_vq_dec_fx`, and through them `dequant_peaks_fx`,
//! `hvq_dec_pos_fx`, `sparse_dec_pos_fx`) against `fn_peak_vq_dec`, comparing the outputs and the
//! whole decoder state (`state_capture.h`) after random bit streams at 24.4 and 32 kbit/s, SWB
//! and FB, including streams shorter than the read and corrupt ones.

use siphon_rtp_codec::evs::dec::peak_vq_dec::{hvq_dec, peak_vq_dec};

use crate::common::{corpus_sized, mismatch, Case};
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

const HQ_CORE: i16 = 3;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// Run one corpus through the Rust function chosen by `through_hvq_dec`; returns how many cases
/// decoded without a bit-error flag and how many raised one, or `None` when the oracle is not built.
fn run(function: &str, through_hvq_dec: bool) -> Option<(usize, usize)> {
    let cases = corpus_sized("peak_vq_dec", function, 200)?;
    let (mut clean, mut flagged) = (0, 0);
    for (index, case) in cases.iter().enumerate() {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let mut st = decoder_before(case);
        let brate = case.i32("brate");
        let mut r = case.i16s("r");
        let mut coefs = vec![0i32; 960];
        let mut peak_idx = [0i16; 23];
        let mut noise_level = [-7i16; 2];
        let mut npeaks = -7i16;
        if through_hvq_dec {
            hvq_dec(
                &mut st,
                case.i16("num_bits"),
                brate,
                &case.i16s("ynrm"),
                &mut r,
                &mut noise_level,
                &mut peak_idx,
                &mut npeaks,
                &mut coefs,
                HQ_CORE,
            );
            check(
                case,
                "noise_level",
                &noise_level.to_vec(),
                &case.out_i16s("noise_level"),
            );
        } else {
            peak_vq_dec(
                &mut st,
                &mut coefs,
                brate as i16,
                case.i16("num_bits"),
                &case.i16s("ynrm"),
                &mut r,
                &mut peak_idx,
                &mut npeaks,
                HQ_CORE,
            );
        }
        let context = format!(
            "case {index}: brate {brate}, bwidth {}, num_bits {}",
            st.bwidth,
            case.i16("num_bits")
        );
        check(case, "coefs", &coefs, &case.out_i32s("coefs"));
        check(case, "r", &r, &case.out_i16s("r"));
        check(
            case,
            "peak_idx",
            &peak_idx.to_vec(),
            &case.out_i16s("peak_idx"),
        );
        check(case, "npeaks", &npeaks, &case.out_i16("npeaks"));
        if st.ber_detect == 0 {
            clean += 1;
        } else {
            flagged += 1;
        }
        state_dump::check(&mut st, &state_after(case), "st.", &context);
    }
    Some((clean, flagged))
}

#[test]
fn hvq_dec_matches_the_reference_on_the_whole_state() {
    let Some((clean, flagged)) = run("hvq_dec", true) else {
        return;
    };
    assert!(
        clean > 20 && flagged > 20,
        "clean {clean}, flagged {flagged}"
    );
}

#[test]
fn peak_vq_dec_matches_the_reference_on_the_whole_state() {
    let Some((clean, flagged)) = run("peak_vq_dec", false) else {
        return;
    };
    assert!(
        clean > 20 && flagged > 20,
        "clean {clean}, flagged {flagged}"
    );
}
