//! Differential test of the STL2009 / EVS basic operators against the TS 26.442 reference C.
//!
//! `reference/evs/oracle/build.sh` compiles `basop_oracle` out of tree from the reference sources
//! (with `-fwrapv`, as the vectors require). Its `corpus` mode prints an edge-heavy pseudo-random
//! set of calls per operator with the reference's results and its `Overflow` / `Carry` globals
//! afterwards; this test replays every call through the Rust port and demands the same answer. The
//! unit tests beside each operator pin a handful of values; this is where the corners get covered.
//!
//! The reference C is copyrighted and gitignored, so this skips when the oracle is absent (a fresh
//! checkout stays green) and `SIPHON_RTP_REQUIRE_VECTORS=1` turns that skip into a failure.
//! `$SIPHON_RTP_EVS_BASOP_ORACLE` points at a build elsewhere, so one build serves every worktree.

#![cfg(feature = "evs")]

use std::path::{Path, PathBuf};
use std::process::Command;

use siphon_rtp_codec::evs::basop;
use siphon_rtp_codec::itu::stl2009::{self, StlFlags};

/// Calls per operator. The corpus is deterministic for a given seed.
const CASES_PER_OPERATOR: &str = "20000";
const SEED: &str = "26442";

fn oracle() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SIPHON_RTP_EVS_BASOP_ORACLE") {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    let in_tree =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/build/basop_oracle");
    in_tree.is_file().then_some(in_tree)
}

fn required() -> bool {
    std::env::var("SIPHON_RTP_REQUIRE_VECTORS").is_ok_and(|value| value == "1")
}

/// The Rust result for one corpus line, rendered the way the oracle prints it: the outputs, then the
/// flags. Operators that do not track the flags echo the incoming ones back, and the comparison
/// below only checks flags for the operators that model them.
fn evaluate(op: &str, a: &[i64], flags_in: StlFlags) -> Option<(Vec<i64>, StlFlags)> {
    let w32 = |index: usize| a[index] as i32;
    let w16 = |index: usize| a[index] as i16;
    let u32_ = |index: usize| a[index] as u32;
    let mut flags = flags_in;
    let outputs: Vec<i64> = match op {
        "L_mult0" => vec![stl2009::l_mult0(w16(0), w16(1)).into()],
        "L_mac0" => vec![stl2009::l_mac0(w32(0), w16(1), w16(2)).into()],
        "L_msu0" => vec![stl2009::l_msu0(w32(0), w16(1), w16(2)).into()],
        "i_mult" => vec![stl2009::i_mult(w16(0), w16(1)).into()],
        "mac_r" => vec![stl2009::mac_r(w32(0), w16(1), w16(2)).into()],
        "msu_r" => vec![stl2009::msu_r(w32(0), w16(1), w16(2)).into()],
        "L_mls" => vec![stl2009::l_mls(w32(0), w16(1)).into()],
        "div_l" => vec![stl2009::div_l(w32(0), w16(1)).into()],
        "lshl" => vec![stl2009::lshl(w16(0), w16(1)).into()],
        "lshr" => vec![stl2009::lshr(w16(0), w16(1)).into()],
        "L_lshl" => vec![stl2009::l_lshl(w32(0), w16(1)).into()],
        "L_lshr" => vec![stl2009::l_lshr(w32(0), w16(1)).into()],
        "shl_r" => vec![stl2009::shl_r(w16(0), w16(1)).into()],
        "L_shl_r" => vec![stl2009::l_shl_r(w32(0), w16(1)).into()],
        "norm_ul" => vec![stl2009::norm_ul(u32_(0)).into()],
        "UL_addNs" => {
            let (sum, wrap) = stl2009::ul_add_ns(u32_(0), u32_(1));
            vec![sum.into(), wrap.into()]
        }
        "UL_subNs" => {
            let (difference, sign) = stl2009::ul_sub_ns(u32_(0), u32_(1));
            vec![difference.into(), sign.into()]
        }
        "Mpy_32_16_uu" => {
            let (high, low) = stl2009::mpy_32_16_uu(u32_(0), a[1] as u16);
            vec![high.into(), low.into()]
        }
        "Mpy_32_32_uu" => {
            let (high, low) = stl2009::mpy_32_32_uu(u32_(0), u32_(1));
            vec![high.into(), low.into()]
        }
        "UL_Mpy_32_32" => vec![stl2009::ul_mpy_32_32(u32_(0), u32_(1)).into()],
        "Mpy_32_16_ss" => {
            let (high, low) = stl2009::mpy_32_16_ss(w32(0), w16(1));
            vec![high.into(), low.into()]
        }
        "Mpy_32_32_ss" => {
            let (high, low) = stl2009::mpy_32_32_ss(w32(0), w32(1));
            vec![high.into(), low.into()]
        }
        "L_add_c" => vec![stl2009::l_add_c(w32(0), w32(1), &mut flags).into()],
        "L_sub_c" => vec![stl2009::l_sub_c(w32(0), w32(1), &mut flags).into()],
        "L_macNs" => vec![stl2009::l_mac_ns(w32(0), w16(1), w16(2), &mut flags).into()],
        "L_msuNs" => vec![stl2009::l_msu_ns(w32(0), w16(1), w16(2), &mut flags).into()],
        "Mpy_32_16_1" => vec![basop::mpy_32_16_1(w32(0), w16(1)).into()],
        "Mpy_32_16_r" => vec![basop::mpy_32_16_r(w32(0), w16(1)).into()],
        "Mpy_32_32" => vec![basop::mpy_32_32(w32(0), w32(1)).into()],
        "Mpy_32_32_r" => vec![basop::mpy_32_32_r(w32(0), w32(1)).into()],
        "Madd_32_16" => vec![basop::madd_32_16(w32(0), w32(1), w16(2)).into()],
        "Msub_32_16" => vec![basop::msub_32_16(w32(0), w32(1), w16(2)).into()],
        "Div_32" => vec![basop::div_32(w32(0), w16(1), w16(2)).into()],
        _ => return None,
    };
    Some((outputs, flags))
}

/// Operators whose `Overflow` / `Carry` side effects the port models, and so are compared too.
fn models_flags(op: &str) -> bool {
    matches!(op, "L_add_c" | "L_sub_c" | "L_macNs" | "L_msuNs")
}

#[test]
fn every_operator_matches_the_reference_over_the_oracle_corpus() {
    let Some(oracle) = oracle() else {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but the EVS basop oracle is not built"
        );
        eprintln!("skipping: EVS basop oracle not built (sh reference/evs/oracle/build.sh)");
        return;
    };
    let output = Command::new(&oracle)
        .args(["corpus", CASES_PER_OPERATOR, SEED])
        .output()
        .unwrap_or_else(|error| panic!("running {oracle:?}: {error}"));
    assert!(output.status.success(), "{oracle:?} failed: {output:?}");
    let corpus = String::from_utf8(output.stdout).expect("oracle prints ASCII");

    let mut checked = 0usize;
    let mut mismatches = Vec::new();
    let mut operators = std::collections::BTreeSet::new();
    for line in corpus.lines() {
        let (call, expected) = line.split_once(" -> ").expect("corpus line has an arrow");
        let mut fields = call.split_whitespace();
        let op = fields.next().expect("operator name");
        let numbers: Vec<i64> = fields
            .map(|field| field.parse().expect("integer operand"))
            .collect();
        let (operands, flag_words) = numbers.split_at(numbers.len() - 2);
        let flags_in = StlFlags {
            overflow: flag_words[0] != 0,
            carry: flag_words[1] != 0,
        };
        let expected: Vec<i64> = expected
            .split_whitespace()
            .map(|field| field.parse().expect("integer result"))
            .collect();
        let (expected_outputs, expected_flags) = expected.split_at(expected.len() - 2);

        let (outputs, flags) =
            evaluate(op, operands, flags_in).unwrap_or_else(|| panic!("no Rust port for {op}"));
        operators.insert(op.to_owned());
        checked += 1;
        let flags_match = !models_flags(op)
            || (flags.overflow == (expected_flags[0] != 0)
                && flags.carry == (expected_flags[1] != 0));
        if outputs != expected_outputs || !flags_match {
            mismatches.push(format!(
                "{line}\n      rust: {outputs:?} overflow={} carry={}",
                flags.overflow, flags.carry
            ));
        }
    }
    assert!(
        checked > 600_000,
        "corpus suspiciously small: {checked} calls"
    );
    assert!(operators.len() >= 33, "corpus covers only {operators:?}");
    assert!(
        mismatches.is_empty(),
        "{} of {checked} calls differ from the reference; first 20:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
