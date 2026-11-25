#![allow(clippy::expect_used, reason = "test harness: a panic reports failure")]
//! The TS 26.442 reference decoder and encoder, built out of tree by `reference/evs/oracle/build.sh`
//! into `reference/evs/build/`, run as independent oracles for the RTP path: `EVS_dec -mime` reads
//! the TS 26.445 A.2.6 storage format, which is the same table of contents and frame bits as a
//! header-full RTP payload of one frame, through the reference's own RTP-side DTX handling.

use std::path::{Path, PathBuf};
use std::process::Command;

fn build_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/evs/build")
}

/// The reference decoder, if it is built.
pub fn decoder() -> Option<PathBuf> {
    let path = build_dir().join("EVS_dec");
    path.is_file().then_some(path)
}

/// The reference encoder, if it is built.
pub fn encoder() -> Option<PathBuf> {
    let path = build_dir().join("EVS_cod");
    path.is_file().then_some(path)
}

pub fn required() -> bool {
    std::env::var("SIPHON_RTP_REQUIRE_ORACLE").is_ok_and(|value| value == "1")
}

/// A scratch directory of this process, unique per call.
pub fn scratch(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "siphon-rtp-evs-{name}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// The storage-format file (`#!EVS_MC1.0`, one channel, then each frame as a table-of-contents
/// octet and its octets) for header-full payloads that carry one frame each, without a CMR octet.
pub fn storage_file(payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut file = b"#!EVS_MC1.0\n".to_vec();
    file.extend_from_slice(&[0, 0, 0, 1]);
    for payload in payloads {
        let frame = if payload[0] & 0x80 != 0 {
            &payload[1..]
        } else {
            &payload[..]
        };
        file.extend_from_slice(frame);
    }
    file
}

/// Decode a storage-format file at `output_khz` with the reference decoder and without its delay
/// compensation, and return the PCM.
pub fn decode_storage(decoder: &Path, file: &[u8], output_khz: usize) -> Vec<i16> {
    let dir = scratch("dec");
    let input = dir.join("in.mime");
    let output = dir.join("out.pcm");
    std::fs::write(&input, file).expect("write storage file");
    let status = Command::new(decoder)
        .args(["-q", "-mime", "-no_delay_cmp", &output_khz.to_string()])
        .arg(&input)
        .arg(&output)
        .output()
        .expect("run EVS_dec");
    assert!(status.status.success(), "EVS_dec: {status:?}");
    let pcm = std::fs::read(&output).expect("EVS_dec output");
    let _ = std::fs::remove_dir_all(&dir);
    pcm.as_chunks::<2>()
        .0
        .iter()
        .map(|pair| i16::from_le_bytes(*pair))
        .collect()
}
