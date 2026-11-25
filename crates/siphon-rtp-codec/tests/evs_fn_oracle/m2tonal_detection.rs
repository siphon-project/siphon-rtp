//! `lib_dec/TonalComponentDetection.c` (`DetectTonalComponents`, `RefineTonalComponents`, and
//! through them every static function of the file) against `fn_m2tonal_detection`: harmonic
//! combs over a noise floor, at the output lengths and core frames the concealment runs with.

use siphon_rtp_codec::evs::dec::tonal_component_detection::{
    detect_tonal_components, refine_tonal_components,
};

use crate::common::{corpus_sized, mismatch, Case};

const MAX_NUMBER_OF_IDX: usize = 30;
const GROUP_LENGTH: usize = 7;

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn detect_tonal_components_matches_the_reference() {
    let Some(cases) = corpus_sized("m2tonal_detection", "detect", 3000) else {
        return;
    };
    let mut found = 0;
    for case in &cases {
        let mut peaks = [0i16; MAX_NUMBER_OF_IDX];
        let mut lower = [0i16; MAX_NUMBER_OF_IDX];
        let mut upper = [0i16; MAX_NUMBER_OF_IDX];
        let mut num_indexes = -1i16;
        detect_tonal_components(
            &mut peaks,
            &mut lower,
            &mut upper,
            &mut num_indexes,
            case.i32("last_pitch_lag"),
            case.i32("current_pitch_lag"),
            &case.i16s("last_spectrum"),
            case.i16("last_spectrum_exp"),
            &case.i16s("scale_factors"),
            &case.i16s("scale_factors_exp"),
            case.i16("scale_factors_max_e"),
            &case.i32s("power_spectrum"),
            case.i16("n_samples"),
            case.i16("n_samples_core"),
            case.i16("floor"),
        );
        check(
            case,
            "num_indexes",
            &num_indexes,
            &case.out_i16("num_indexes"),
        );
        check(
            case,
            "index_of_tonal_peak",
            &peaks.to_vec(),
            &case.out_i16s("index_of_tonal_peak"),
        );
        check(case, "lower", &lower.to_vec(), &case.out_i16s("lower"));
        check(case, "upper", &upper.to_vec(), &case.out_i16s("upper"));
        found += usize::from(num_indexes > 0);
    }
    assert!(
        found > cases.len() / 4,
        "only {found} of {} cases found tonal components",
        cases.len()
    );
}

#[test]
fn refine_tonal_components_matches_the_reference() {
    let Some(cases) = corpus_sized("m2tonal_detection", "refine", 3000) else {
        return;
    };
    let (mut kept, mut dropped) = (0, 0);
    for case in &cases {
        let mut peaks: [i16; MAX_NUMBER_OF_IDX] =
            case.i16s("old_index_of_tonal_peak").try_into().unwrap();
        let mut lower: [i16; MAX_NUMBER_OF_IDX] = case.i16s("old_lower").try_into().unwrap();
        let mut upper: [i16; MAX_NUMBER_OF_IDX] = case.i16s("old_upper").try_into().unwrap();
        let mut phase_diff: [i16; MAX_NUMBER_OF_IDX] =
            case.i16s("old_phase_diff").try_into().unwrap();
        let mut phases: [i16; MAX_NUMBER_OF_IDX * GROUP_LENGTH] =
            case.i16s("old_phases").try_into().unwrap();
        let old_num_indexes = case.i16("old_num_indexes");
        let mut num_indexes = old_num_indexes;
        refine_tonal_components(
            &mut peaks,
            &mut lower,
            &mut upper,
            &mut phase_diff,
            &mut phases,
            &mut num_indexes,
            case.i32("last_pitch_lag"),
            case.i32("current_pitch_lag"),
            &case.i16s("last_spectrum"),
            case.i16("last_spectrum_exp"),
            &case.i16s("scale_factors"),
            &case.i16s("scale_factors_exp"),
            case.i16("scale_factors_max_e"),
            &case.i32s("new_power_spectrum"),
            case.i16("n_samples"),
            case.i16("n_samples_core"),
            case.i16("floor"),
        );
        check(
            case,
            "num_indexes",
            &num_indexes,
            &case.out_i16("num_indexes"),
        );
        check(
            case,
            "index_of_tonal_peak",
            &peaks.to_vec(),
            &case.out_i16s("index_of_tonal_peak"),
        );
        check(case, "lower", &lower.to_vec(), &case.out_i16s("lower"));
        check(case, "upper", &upper.to_vec(), &case.out_i16s("upper"));
        check(
            case,
            "phase_diff",
            &phase_diff.to_vec(),
            &case.out_i16s("phase_diff"),
        );
        check(case, "phases", &phases.to_vec(), &case.out_i16s("phases"));
        kept += usize::from(num_indexes > 0);
        dropped += usize::from(num_indexes < old_num_indexes);
    }
    assert!(kept > cases.len() / 5, "only {kept} cases kept a component");
    assert!(dropped > 0, "no case dropped a component");
}
