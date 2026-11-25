//! The TS 26.444 decoder cases as upstream's own scripts list them, shared by the EVS conformance
//! and zero-allocation tests (a directory module, so cargo does not build it as a test of its own).

use std::path::{Path, PathBuf};

/// One `$DEC_BIN rate in out` line and the `$DIFF_BIN reference out` line that follows it.
pub struct Case {
    pub output_khz: usize,
    pub bitstream: PathBuf,
    pub reference: PathBuf,
}

pub fn vectors_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("SIPHON_RTP_EVS_VECTORS") {
        let path = PathBuf::from(path);
        return path.is_dir().then_some(path);
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/testvec");
    dir.is_dir().then_some(dir)
}

pub fn required() -> bool {
    std::env::var("SIPHON_RTP_REQUIRE_VECTORS").is_ok_and(|value| value == "1")
}

pub fn cases(root: &Path, script: &str) -> Vec<Case> {
    let text = std::fs::read_to_string(root.join(script))
        .unwrap_or_else(|error| panic!("reading {script}: {error}"));
    let mut cases = Vec::new();
    let mut pending: Option<(usize, PathBuf)> = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.first() {
            Some(&"$DEC_BIN") => {
                // `$DEC_BIN <kHz> <in> <out>`. Every decoder case upstream ships takes the output
                // rate and nothing else; an option appearing here means the script changed under
                // us, and is refused rather than silently ignored.
                assert_eq!(
                    fields.len(),
                    4,
                    "{script}: unexpected decoder options in {line:?}"
                );
                let output_khz = fields[1]
                    .parse()
                    .unwrap_or_else(|_| panic!("{script}: {line:?}"));
                pending = Some((output_khz, root.join(fields[2])));
            }
            Some(&"$DIFF_BIN") => {
                if let Some((output_khz, bitstream)) = pending.take() {
                    cases.push(Case {
                        output_khz,
                        bitstream,
                        reference: root.join(fields[1]),
                    });
                }
            }
            _ => {}
        }
    }
    cases
}

// Only the RTP tests wrap frames into payloads.
#[allow(dead_code)]
pub mod packetize;

// The reference's own decoders, built out of tree (`sh reference/evs/oracle/build.sh`).
#[allow(dead_code)]
pub mod oracle;
