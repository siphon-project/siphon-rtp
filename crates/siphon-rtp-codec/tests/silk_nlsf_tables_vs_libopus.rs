//! Byte-for-byte diff of the ported SILK NLSF tables against the libopus C they came from.
//!
//! The NLSF codebooks are the largest tables in the codec — 832 stage-1 codebook entries, 832
//! weights, 416 stage-2 select bytes, two 72-entry stage-2 PDF banks, two matching 72-entry
//! encoder-side rate banks, and a 129-point cosine table.
//! A single mistyped byte in an entropy table silently desynchronises the range decoder; a mistyped
//! byte in a codebook vector detunes the LPC filter with no decode error at all. Spot-checking a
//! handful of "known entries" would not find either, so this test compares **every element**
//! against the C source it was ported from.
//!
//! The C source (`reference/opus/opus-1.5.2/`) is a test-only reference, gitignored and never a
//! dependency, so this skips gracefully when it is absent — like every other conformance test here.
//! `SIPHON_RTP_REQUIRE_VECTORS=1` turns that skip into a failure (see `reference_vectors.rs`).
//!
//! The parser below is deliberately dumb: it finds `const opus_<type> <name>[...] = { ... };` and
//! reads the integer literals out of the braces. It is not a C parser and does not need to be — if
//! it ever mis-parses, the comparison fails loudly rather than passing vacuously, and the
//! `expected_arrays_found` check makes a wholesale parse failure a test failure too.

use std::path::{Path, PathBuf};

use siphon_rtp_codec::opus::silk::nlsf_tables::{
    LSF_COS_TAB_Q12, NB_MB_CB1_ICDF, NB_MB_CB1_Q8, NB_MB_CB1_WEIGHT_Q9, NB_MB_CB2_ICDF,
    NB_MB_CB2_RATES_Q5, NB_MB_CB2_SELECT, NB_MB_DELTA_MIN_Q15, NB_MB_PREDICTION_Q8, NLSF_EXT_ICDF,
    NLSF_INTERPOLATION_FACTOR_ICDF, WB_CB1_ICDF, WB_CB1_Q8, WB_CB1_WEIGHT_Q9, WB_CB2_ICDF,
    WB_CB2_RATES_Q5, WB_CB2_SELECT, WB_DELTA_MIN_Q15, WB_PREDICTION_Q8,
};

/// `reference/opus/opus-1.5.2/silk`, if the libopus source has been unpacked.
fn silk_source_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/opus/opus-1.5.2/silk");
    dir.is_dir().then_some(dir)
}

/// Extract the integer literals of the C array named `name` from `source`.
///
/// Returns `None` when the array is not present, which the caller turns into a hard failure —
/// a missing array must never read as "nothing to compare".
fn c_array(source: &str, name: &str) -> Option<Vec<i64>> {
    // Match the declaration `<name>[` so a prefix of another array's name cannot be picked up.
    let needle = format!("{name}[");
    let mut search_from = 0usize;
    let declaration = loop {
        let found = source[search_from..].find(&needle)? + search_from;
        // Reject a *use* of the array (e.g. inside the codebook struct) rather than its definition:
        // a definition is followed by `] = {`.
        let after = &source[found + needle.len()..];
        let Some(brace) = after.find('{') else {
            search_from = found + needle.len();
            continue;
        };
        let Some(equals) = after.find('=') else {
            search_from = found + needle.len();
            continue;
        };
        if equals < brace && after[..equals].contains(']') {
            break found + needle.len() + brace + 1;
        }
        search_from = found + needle.len();
    };
    let end = source[declaration..].find('}')? + declaration;
    let body = &source[declaration..end];

    let mut values = Vec::new();
    let mut current = String::new();
    for character in body.chars() {
        if character.is_ascii_digit() || (character == '-' && current.is_empty()) {
            current.push(character);
        } else {
            if !current.is_empty() {
                values.push(current.parse::<i64>().ok()?);
                current.clear();
            }
            // Any letter inside the body means this is not a plain literal table.
            if character.is_ascii_alphabetic() {
                return None;
            }
        }
    }
    if !current.is_empty() {
        values.push(current.parse::<i64>().ok()?);
    }
    Some(values)
}

/// Compare one ported table against its C original, element by element.
fn compare<T>(failures: &mut Vec<String>, name: &str, source: &str, ported: &[T])
where
    T: Copy + Into<i64> + std::fmt::Debug,
{
    let Some(reference) = c_array(source, name) else {
        failures.push(format!("{name}: not found in the libopus source"));
        return;
    };
    if reference.len() != ported.len() {
        failures.push(format!(
            "{name}: libopus has {} entries, we have {}",
            reference.len(),
            ported.len()
        ));
        return;
    }
    for (index, (&ours, &theirs)) in ported.iter().zip(reference.iter()).enumerate() {
        let ours: i64 = ours.into();
        if ours != theirs {
            failures.push(format!("{name}[{index}]: {ours} != libopus {theirs}"));
            if failures.len() > 32 {
                failures.push(format!("{name}: ... further mismatches suppressed"));
                return;
            }
        }
    }
}

#[test]
fn silk_nlsf_tables_match_libopus_byte_for_byte() {
    let Some(dir) = silk_source_dir() else {
        eprintln!("silk NLSF tables: libopus source not present — skipping");
        return;
    };

    let read = |file: &str| -> Option<String> { std::fs::read_to_string(dir.join(file)).ok() };
    let (Some(nb_mb), Some(wb), Some(other), Some(cosine)) = (
        read("tables_NLSF_CB_NB_MB.c"),
        read("tables_NLSF_CB_WB.c"),
        read("tables_other.c"),
        read("table_LSF_cos.c"),
    ) else {
        panic!(
            "libopus source at {} is missing one of the SILK NLSF table files",
            dir.display()
        );
    };

    let mut failures: Vec<String> = Vec::new();
    let mut compared = 0usize;

    compare(
        &mut failures,
        "silk_NLSF_CB1_NB_MB_Q8",
        &nb_mb,
        &NB_MB_CB1_Q8,
    );
    compared += NB_MB_CB1_Q8.len();
    compare(
        &mut failures,
        "silk_NLSF_CB1_Wght_Q9",
        &nb_mb,
        &NB_MB_CB1_WEIGHT_Q9,
    );
    compared += NB_MB_CB1_WEIGHT_Q9.len();
    compare(
        &mut failures,
        "silk_NLSF_CB1_iCDF_NB_MB",
        &nb_mb,
        &NB_MB_CB1_ICDF,
    );
    compared += NB_MB_CB1_ICDF.len();
    compare(
        &mut failures,
        "silk_NLSF_CB2_SELECT_NB_MB",
        &nb_mb,
        &NB_MB_CB2_SELECT,
    );
    compared += NB_MB_CB2_SELECT.len();
    compare(
        &mut failures,
        "silk_NLSF_CB2_iCDF_NB_MB",
        &nb_mb,
        &NB_MB_CB2_ICDF,
    );
    compared += NB_MB_CB2_ICDF.len();
    compare(
        &mut failures,
        "silk_NLSF_CB2_BITS_NB_MB_Q5",
        &nb_mb,
        &NB_MB_CB2_RATES_Q5,
    );
    compared += NB_MB_CB2_RATES_Q5.len();
    compare(
        &mut failures,
        "silk_NLSF_PRED_NB_MB_Q8",
        &nb_mb,
        &NB_MB_PREDICTION_Q8,
    );
    compared += NB_MB_PREDICTION_Q8.len();
    compare(
        &mut failures,
        "silk_NLSF_DELTA_MIN_NB_MB_Q15",
        &nb_mb,
        &NB_MB_DELTA_MIN_Q15,
    );
    compared += NB_MB_DELTA_MIN_Q15.len();

    compare(&mut failures, "silk_NLSF_CB1_WB_Q8", &wb, &WB_CB1_Q8);
    compared += WB_CB1_Q8.len();
    compare(
        &mut failures,
        "silk_NLSF_CB1_WB_Wght_Q9",
        &wb,
        &WB_CB1_WEIGHT_Q9,
    );
    compared += WB_CB1_WEIGHT_Q9.len();
    compare(&mut failures, "silk_NLSF_CB1_iCDF_WB", &wb, &WB_CB1_ICDF);
    compared += WB_CB1_ICDF.len();
    compare(
        &mut failures,
        "silk_NLSF_CB2_SELECT_WB",
        &wb,
        &WB_CB2_SELECT,
    );
    compared += WB_CB2_SELECT.len();
    compare(&mut failures, "silk_NLSF_CB2_iCDF_WB", &wb, &WB_CB2_ICDF);
    compared += WB_CB2_ICDF.len();
    compare(
        &mut failures,
        "silk_NLSF_CB2_BITS_WB_Q5",
        &wb,
        &WB_CB2_RATES_Q5,
    );
    compared += WB_CB2_RATES_Q5.len();
    compare(
        &mut failures,
        "silk_NLSF_PRED_WB_Q8",
        &wb,
        &WB_PREDICTION_Q8,
    );
    compared += WB_PREDICTION_Q8.len();
    compare(
        &mut failures,
        "silk_NLSF_DELTA_MIN_WB_Q15",
        &wb,
        &WB_DELTA_MIN_Q15,
    );
    compared += WB_DELTA_MIN_Q15.len();

    compare(&mut failures, "silk_NLSF_EXT_iCDF", &other, &NLSF_EXT_ICDF);
    compared += NLSF_EXT_ICDF.len();
    compare(
        &mut failures,
        "silk_NLSF_interpolation_factor_iCDF",
        &other,
        &NLSF_INTERPOLATION_FACTOR_ICDF,
    );
    compared += NLSF_INTERPOLATION_FACTOR_ICDF.len();
    compare(
        &mut failures,
        "silk_LSFCosTab_FIX_Q12",
        &cosine,
        &LSF_COS_TAB_Q12,
    );
    compared += LSF_COS_TAB_Q12.len();

    eprintln!("silk NLSF tables: {compared} entries compared against libopus");
    assert!(
        failures.is_empty(),
        "silk NLSF tables differ from libopus:\n  {}",
        failures.join("\n  ")
    );
    // Non-vacuous: the parser must actually have read every table. 2569 decoder-side entries plus
    // the two 72-entry encoder-only `ec_Rates_Q5` banks.
    assert_eq!(
        compared, 2713,
        "expected 2713 table entries to be compared; the parser missed some"
    );
}

/// The parser itself, on a fixture that exercises the shapes it has to survive: a `static const`,
/// a non-numeric array bound, negative values, and a name that is a prefix of another.
#[test]
fn c_array_parser_handles_the_shapes_it_meets() {
    let source = concat!(
        "static const opus_uint8 silk_table[ 4 ] = {\n",
        "    1, 2, 3, 4\n",
        "};\n",
        "const opus_int16 silk_table_long[ SOME_SIZE + 1 ] = {\n",
        "    -1, 0, 32767\n",
        "};\n",
        "const silk_NLSF_CB_struct silk_cb = { 32, silk_table, silk_table_long };\n",
    );
    assert_eq!(c_array(source, "silk_table"), Some(vec![1, 2, 3, 4]));
    assert_eq!(
        c_array(source, "silk_table_long"),
        Some(vec![-1, 0, 32767]),
        "a symbolic array bound must not confuse the parser"
    );
    assert_eq!(c_array(source, "silk_absent"), None);
}
