//! Running a function-level oracle (`reference/evs/build/fn_<module>`) and reading its corpus.
//!
//! The oracle prints one line per call, `name=v,v name=v -> name=v,v ...`, inputs left of the arrow
//! and outputs right of it (see `reference/evs/oracle/fn/harness.h`). A test replays each line through
//! the Rust port and compares the outputs.

#![allow(dead_code)] // each test module uses the accessors it needs

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

/// Calls per function in the default corpus.
pub const CASES: usize = 2000;
/// Corpus seed; fixed, so a failure reproduces.
pub const SEED: u64 = 26442;

/// One oracle call: named integer vectors on each side of the arrow.
#[derive(Debug, Clone)]
pub struct Case {
    pub line: String,
    pub inputs: BTreeMap<String, Vec<i64>>,
    pub outputs: BTreeMap<String, Vec<i64>>,
}

fn field(map: &BTreeMap<String, Vec<i64>>, name: &str, line: &str) -> Vec<i64> {
    map.get(name)
        .unwrap_or_else(|| panic!("no field {name} in {line}"))
        .clone()
}

impl Case {
    pub fn i16s(&self, name: &str) -> Vec<i16> {
        field(&self.inputs, name, &self.line)
            .into_iter()
            .map(|v| v as i16)
            .collect()
    }
    pub fn i32s(&self, name: &str) -> Vec<i32> {
        field(&self.inputs, name, &self.line)
            .into_iter()
            .map(|v| v as i32)
            .collect()
    }
    pub fn i16(&self, name: &str) -> i16 {
        self.i16s(name)[0]
    }
    pub fn i32(&self, name: &str) -> i32 {
        self.i32s(name)[0]
    }
    pub fn out_i16s(&self, name: &str) -> Vec<i16> {
        field(&self.outputs, name, &self.line)
            .into_iter()
            .map(|v| v as i16)
            .collect()
    }
    pub fn out_i32s(&self, name: &str) -> Vec<i32> {
        field(&self.outputs, name, &self.line)
            .into_iter()
            .map(|v| v as i32)
            .collect()
    }
    pub fn out_i16(&self, name: &str) -> i16 {
        self.out_i16s(name)[0]
    }
    pub fn out_i32(&self, name: &str) -> i32 {
        self.out_i32s(name)[0]
    }
}

fn parse_side(text: &str) -> BTreeMap<String, Vec<i64>> {
    text.split_whitespace()
        .map(|pair| {
            let (name, values) = pair.split_once('=').expect("name=values");
            let values = if values.is_empty() {
                Vec::new()
            } else {
                values
                    .split(',')
                    .map(|v| v.parse().expect("integer"))
                    .collect()
            };
            (name.to_owned(), values)
        })
        .collect()
}

fn required() -> bool {
    std::env::var("SIPHON_RTP_REQUIRE_VECTORS").is_ok_and(|value| value == "1")
}

fn oracle_path(module: &str) -> PathBuf {
    let build = std::env::var_os("SIPHON_RTP_EVS_ORACLE_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/build"),
        PathBuf::from,
    );
    build.join(format!("fn_{module}"))
}

/// The corpus for `function` from oracle `module`, or `None` (after a note) when that oracle is not
/// built and vectors are not required. `SIPHON_RTP_EVS_ORACLE_DIR` points at a build directory
/// elsewhere, so one build serves every worktree.
pub fn corpus(module: &str, function: &str) -> Option<Vec<Case>> {
    corpus_sized(module, function, CASES)
}

pub fn corpus_sized(module: &str, function: &str, count: usize) -> Option<Vec<Case>> {
    let path = oracle_path(module);
    if !path.is_file() {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but {path:?} is not built"
        );
        eprintln!("skipping: {path:?} not built (sh reference/evs/oracle/build.sh)");
        return None;
    }
    let output = Command::new(&path)
        .args(["corpus", function, &count.to_string(), &SEED.to_string()])
        .output()
        .unwrap_or_else(|error| panic!("running {path:?}: {error}"));
    assert!(
        output.status.success(),
        "{path:?} {function} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("ASCII corpus");
    let cases: Vec<Case> = text
        .lines()
        .map(|line| {
            let (inputs, outputs) = line.split_once(" ->").expect("corpus line has an arrow");
            Case {
                line: line.to_owned(),
                inputs: parse_side(inputs),
                outputs: parse_side(outputs),
            }
        })
        .collect();
    assert_eq!(
        cases.len(),
        count,
        "{function}: oracle printed {} of {count} cases",
        cases.len()
    );
    Some(cases)
}

/// Run `function` of oracle `module` for `count` cases from `seed` and hand each case to `visit` as the
/// oracle prints it, without keeping the others (a stress corpus is too large to hold). Returns the number of
/// cases, or `None` (after a note) when the oracle is not built and vectors are not required.
pub fn stream_cases(
    module: &str,
    function: &str,
    count: usize,
    seed: u64,
    mut visit: impl FnMut(&Case),
) -> Option<usize> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let path = oracle_path(module);
    if !path.is_file() {
        assert!(
            !required(),
            "SIPHON_RTP_REQUIRE_VECTORS=1 but {path:?} is not built"
        );
        eprintln!("skipping: {path:?} not built (sh reference/evs/oracle/build.sh)");
        return None;
    }
    let mut child = Command::new(&path)
        .args(["corpus", function, &count.to_string(), &seed.to_string()])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("running {path:?}: {error}"));
    let reader = BufReader::new(child.stdout.take().expect("piped stdout"));
    let mut seen = 0;
    for line in reader.lines() {
        let line = line.expect("ASCII corpus");
        let (inputs, outputs) = line.split_once(" ->").expect("corpus line has an arrow");
        let case = Case {
            inputs: parse_side(inputs),
            outputs: parse_side(outputs),
            line: line.clone(),
        };
        visit(&case);
        seen += 1;
    }
    let status = child.wait().expect("oracle exit status");
    assert!(status.success(), "{path:?} {function} failed: {status}");
    assert_eq!(
        seen, count,
        "{function}: oracle printed {seen} of {count} cases"
    );
    Some(seen)
}

/// Compare one output and describe the first mismatching case, for an `assert!` message.
pub fn mismatch<T: PartialEq + std::fmt::Debug>(
    case: &Case,
    name: &str,
    rust: &T,
    reference: &T,
) -> Option<String> {
    (rust != reference).then(|| {
        format!(
            "{name} differs\n  case: {}\n  rust: {rust:?}\n  ref:  {reference:?}",
            case.line
        )
    })
}
