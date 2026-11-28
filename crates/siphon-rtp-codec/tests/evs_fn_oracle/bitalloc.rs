//! `lib_com/bitalloc_fx.c` against `fn_bitalloc`: the integer allocation, the fractional SWB
//! allocation and the 32 kbit/s WB allocation (with its group allocation), on the inputs the
//! HQ high-rate bit allocation gives them.

use siphon_rtp_codec::evs::com::bitalloc::{bit_alloc_f, bit_alloc_wb, bitalloc};

use crate::common::{corpus, mismatch, stream_cases};

fn check(messages: impl IntoIterator<Item = Option<String>>) {
    if let Some(message) = messages.into_iter().flatten().next() {
        panic!("{message}");
    }
}

#[test]
fn bitalloc_matches_the_reference() {
    let Some(cases) = corpus("bitalloc", "bitalloc") else {
        return;
    };
    let mut checked = 0;
    for case in &cases {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let mut y = case.i16s("y");
        let mut r = [0i16; 44];
        bitalloc(
            &mut y,
            &case.i16s("idx"),
            case.i16("sum"),
            case.i16("n"),
            case.i16("k"),
            &mut r,
            &case.i16s("sfmsize"),
            case.i16("hqswb_clas"),
        );
        check([
            mismatch(case, "y", &y, &case.out_i16s("y")),
            mismatch(case, "r", &r.to_vec(), &case.out_i16s("r")),
        ]);
        checked += 1;
    }
    assert!(checked > 1900, "{checked} cases reached the function");
}

#[test]
fn bit_alloc_f_matches_the_reference() {
    let Some(cases) = corpus("bitalloc", "bit_alloc_f") else {
        return;
    };
    let mut checked = 0;
    for case in &cases {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let n = case.i16("n") as usize;
        let mut r = [-7i16; 44];
        let mut rsubband = [-7i16; 44];
        let used = bit_alloc_f(
            &case.i16s("y"),
            case.i32("bit_rate"),
            case.i16("b"),
            case.i16("n"),
            &mut r,
            &mut rsubband,
            case.i16("hqswb_clas"),
            case.i16("num_env_bands"),
        );
        check([
            mismatch(case, "used", &used, &case.out_i16("used")),
            mismatch(case, "r", &r[..n].to_vec(), &case.out_i16s("r")),
            mismatch(
                case,
                "rsubband",
                &rsubband[..n].to_vec(),
                &case.out_i16s("rsubband"),
            ),
        ]);
        checked += 1;
    }
    assert!(checked > 1900, "{checked} cases reached the function");
}

#[test]
fn bit_alloc_wb_matches_the_reference() {
    let Some(cases) = corpus("bitalloc", "bit_alloc_wb") else {
        return;
    };
    let mut checked = 0;
    for case in &cases {
        if case.outputs.contains_key("skip") {
            continue;
        }
        let n = case.i16("n") as usize;
        let mut r = [-7i16; 44];
        let mut rsubband = [-7i16; 44];
        let used = bit_alloc_wb(
            &case.i16s("y"),
            case.i16("b"),
            case.i16("n"),
            &mut r,
            &mut rsubband,
        );
        check([
            mismatch(case, "used", &used, &case.out_i16("used")),
            mismatch(case, "r", &r[..n].to_vec(), &case.out_i16s("r")),
            mismatch(
                case,
                "rsubband",
                &rsubband[..n].to_vec(),
                &case.out_i16s("rsubband"),
            ),
        ]);
        checked += 1;
    }
    assert!(checked > 1900, "{checked} cases reached the function");
}

/// Cases per stress run: wide budgets, short band counts and solved zero shares (`bitalloc_wide`,
/// `bit_alloc_f_wide`), streamed so that the corpus is never held in memory.
const STRESS_CASES: usize = 1_000_000;
const STRESS_SEED: u64 = 7_300_117;

#[test]
fn bitalloc_matches_the_reference_on_wide_budgets() {
    let mut checked = 0;
    let seen = stream_cases(
        "bitalloc",
        "bitalloc_wide",
        STRESS_CASES,
        STRESS_SEED,
        |case| {
            if case.outputs.contains_key("skip") {
                return;
            }
            let n = case.i16("n") as usize;
            let mut y = case.i16s("y");
            let mut r = [0i16; 44];
            bitalloc(
                &mut y,
                &case.i16s("idx"),
                case.i16("sum"),
                case.i16("n"),
                case.i16("k"),
                &mut r,
                &case.i16s("sfmsize"),
                case.i16("hqswb_clas"),
            );
            assert_eq!(y.len(), n);
            check([
                mismatch(case, "y", &y, &case.out_i16s("y")),
                mismatch(case, "r", &r.to_vec(), &case.out_i16s("r")),
            ]);
            checked += 1;
        },
    );
    if seen.is_some() {
        assert!(
            checked > STRESS_CASES / 2,
            "{checked} cases reached the function"
        );
    }
}

#[test]
fn bit_alloc_f_matches_the_reference_on_wide_budgets() {
    let mut checked = 0;
    let seen = stream_cases(
        "bitalloc",
        "bit_alloc_f_wide",
        STRESS_CASES,
        STRESS_SEED,
        |case| {
            if case.outputs.contains_key("skip") {
                return;
            }
            let n = case.i16("n") as usize;
            let mut r = [-7i16; 44];
            let mut rsubband = [-7i16; 44];
            let used = bit_alloc_f(
                &case.i16s("y"),
                case.i32("bit_rate"),
                case.i16("b"),
                case.i16("n"),
                &mut r,
                &mut rsubband,
                case.i16("hqswb_clas"),
                case.i16("num_env_bands"),
            );
            check([
                mismatch(case, "used", &used, &case.out_i16("used")),
                mismatch(case, "r", &r[..n].to_vec(), &case.out_i16s("r")),
                mismatch(
                    case,
                    "rsubband",
                    &rsubband[..n].to_vec(),
                    &case.out_i16s("rsubband"),
                ),
            ]);
            checked += 1;
        },
    );
    if seen.is_some() {
        assert!(
            checked > STRESS_CASES / 2,
            "{checked} cases reached the function"
        );
    }
}

/// The first-pass corpus of the 32 kbit/s WB allocation, 150 times larger (streamed).
#[test]
fn bit_alloc_wb_matches_the_reference_on_a_large_corpus() {
    let mut checked = 0;
    let seen = stream_cases(
        "bitalloc",
        "bit_alloc_wb",
        STRESS_CASES,
        STRESS_SEED,
        |case| {
            if case.outputs.contains_key("skip") {
                return;
            }
            let n = case.i16("n") as usize;
            let mut r = [-7i16; 44];
            let mut rsubband = [-7i16; 44];
            let used = bit_alloc_wb(
                &case.i16s("y"),
                case.i16("b"),
                case.i16("n"),
                &mut r,
                &mut rsubband,
            );
            check([
                mismatch(case, "used", &used, &case.out_i16("used")),
                mismatch(case, "r", &r[..n].to_vec(), &case.out_i16s("r")),
                mismatch(
                    case,
                    "rsubband",
                    &rsubband[..n].to_vec(),
                    &case.out_i16s("rsubband"),
                ),
            ]);
            checked += 1;
        },
    );
    if seen.is_some() {
        assert!(
            checked > STRESS_CASES / 2,
            "{checked} cases reached the function"
        );
    }
}

/// Budgets on which the second group's share is exactly two or three short of rounding up (searched
/// by the oracle over every triple of flat group levels), so the rounding comparisons are decided
/// by their last bit.
#[test]
fn bit_alloc_wb_matches_the_reference_on_the_rounding_boundary() {
    let mut checked = 0;
    let mut most_hits = 0;
    let seen = stream_cases(
        "bitalloc",
        "bit_alloc_wb_boundary",
        4000,
        STRESS_SEED,
        |case| {
            if case.outputs.contains_key("skip") {
                return;
            }
            most_hits = most_hits.max(case.i32("hits"));
            let n = case.i16("n") as usize;
            let mut r = [-7i16; 44];
            let mut rsubband = [-7i16; 44];
            let used = bit_alloc_wb(
                &case.i16s("y"),
                case.i16("b"),
                case.i16("n"),
                &mut r,
                &mut rsubband,
            );
            check([
                mismatch(case, "used", &used, &case.out_i16("used")),
                mismatch(case, "r", &r[..n].to_vec(), &case.out_i16s("r")),
                mismatch(
                    case,
                    "rsubband",
                    &rsubband[..n].to_vec(),
                    &case.out_i16s("rsubband"),
                ),
            ]);
            checked += 1;
        },
    );
    if seen.is_some() {
        assert!(checked > 0);
        assert!(most_hits > 0, "the oracle found no boundary budget");
    }
}

/// `bit_alloc_f` on budgets too small for the bands that ask for bits, norms falling away towards the
/// high bands.
#[test]
fn bit_alloc_f_matches_the_reference_on_scarce_budgets() {
    let mut checked = 0;
    let seen = stream_cases(
        "bitalloc",
        "bit_alloc_f_scarce",
        STRESS_CASES,
        STRESS_SEED,
        |case| {
            if case.outputs.contains_key("skip") {
                return;
            }
            let n = case.i16("n") as usize;
            let mut r = [-7i16; 44];
            let mut rsubband = [-7i16; 44];
            let used = bit_alloc_f(
                &case.i16s("y"),
                case.i32("bit_rate"),
                case.i16("b"),
                case.i16("n"),
                &mut r,
                &mut rsubband,
                case.i16("hqswb_clas"),
                case.i16("num_env_bands"),
            );
            check([
                mismatch(case, "used", &used, &case.out_i16("used")),
                mismatch(case, "r", &r[..n].to_vec(), &case.out_i16s("r")),
                mismatch(
                    case,
                    "rsubband",
                    &rsubband[..n].to_vec(),
                    &case.out_i16s("rsubband"),
                ),
            ]);
            checked += 1;
        },
    );
    if seen.is_some() {
        assert!(
            checked > STRESS_CASES / 2,
            "{checked} cases reached the function"
        );
    }
}

/// A norm vector and budget for which the Q21 allocation total sits 8 short of a unit of the final
/// shift, so the reported bits depend on every Q21 step the group allocations leave behind.
#[test]
fn bit_alloc_wb_matches_the_reference_on_a_total_8_short_of_a_unit() {
    let mut checked = 0;
    let seen = stream_cases("bitalloc", "bit_alloc_wb_carry", 1, STRESS_SEED, |case| {
        assert!(!case.outputs.contains_key("skip"));
        let n = case.i16("n") as usize;
        let mut r = [-7i16; 44];
        let mut rsubband = [-7i16; 44];
        let used = bit_alloc_wb(
            &case.i16s("y"),
            case.i16("b"),
            case.i16("n"),
            &mut r,
            &mut rsubband,
        );
        check([
            mismatch(case, "used", &used, &case.out_i16("used")),
            mismatch(case, "r", &r[..n].to_vec(), &case.out_i16s("r")),
            mismatch(
                case,
                "rsubband",
                &rsubband[..n].to_vec(),
                &case.out_i16s("rsubband"),
            ),
        ]);
        checked += 1;
    });
    if seen.is_some() {
        assert_eq!(checked, 1);
    }
}
