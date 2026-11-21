//! `lib_dec/hq_classifier_dec_fx.c` against `fn_hq_classifier_dec`: random class bits (sometimes
//! too few, taking the bit-error path), outputs and the whole decoder state compared.

use siphon_rtp_codec::evs::dec::hq_classifier_dec::hq_classifier_dec;

use crate::common::{corpus, mismatch, Case};
use crate::state_case::{decoder_before, state_after};
use crate::state_dump;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn hq_classifier_dec_matches_the_reference() {
    let Some(cases) = corpus("hq_classifier_dec", "hq_classifier_dec") else {
        return;
    };
    let mut classes = std::collections::BTreeSet::new();
    for (index, case) in cases.iter().enumerate() {
        let mut st = decoder_before(case);
        let (mut is_transient, mut hqswb_clas) = (-7, -7);
        let bits = hq_classifier_dec(
            &mut st,
            case.i32("core_brate"),
            case.i16("length"),
            &mut is_transient,
            &mut hqswb_clas,
        );
        check(case, "bits", &bits, &case.out_i16("bits"));
        check(
            case,
            "is_transient",
            &is_transient,
            &case.out_i16("is_transient"),
        );
        check(case, "hqswb_clas", &hqswb_clas, &case.out_i16("hqswb_clas"));
        let context = format!("case {index}");
        state_dump::check(&mut st, &state_after(case), "st.", &context);
        classes.insert(hqswb_clas);
    }
    assert!(classes.len() >= 5, "classes {classes:?}");
}
