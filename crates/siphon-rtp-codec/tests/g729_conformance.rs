//! Bit-exact conformance of the G.729 decoder against the official ITU-T test sequences.
//!
//! Upstream generated every sequence by running the reference binaries in each direction, so the
//! files pin both independently: `coder file.in file.bit`, then `decoder file.bit file.pst`. This
//! test takes the decode half — every `*.bit` must produce its `*.pst` byte for byte — which is a
//! claim a round trip could never make, since a shared encode/decode bug passes one and fails here.
//!
//! The vectors are copyrighted and gitignored, so this skips when they are absent (which keeps a
//! fresh checkout green) and `SIPHON_RTP_REQUIRE_VECTORS=1` turns that skip into a hard failure.
//! `reference/g729/README.md` says where to get them; `sh reference/g729/fetch.sh` does it.

#![cfg(feature = "g729")]

use std::path::{Path, PathBuf};

use siphon_rtp_codec::g729::G729Decoder;

/// The sequences and what each is designed to exercise, per upstream's own `readmetv.txt`.
const SEQUENCES: &[(&str, &str)] = &[
    ("algthm", "conditional parts of the algorithm"),
    ("erasure", "frame-erasure recovery"),
    ("fixed", "fixed (algebraic) codebook search"),
    ("lsp", "LSP quantization"),
    ("overflow", "overflow detection in the synthesizer"),
    ("parity", "parity check on the pitch delay"),
    ("pitch", "pitch search"),
    ("speech", "generic speech"),
    ("tame", "the taming procedure"),
];

/// Words per frame in the ITU serial file format: a sync word, a length, then one word per bit.
const SERIAL_WORDS: usize = 82;
/// The reference's marker for a set bit; anything else in that position is a clear bit, and an
/// all-zero frame is how the format flags an erasure.
const BIT_SET: i16 = 0x0081;

fn vectors_dir() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../reference/g729/testv/base");
    dir.is_dir().then_some(dir)
}

fn read_words(path: &Path) -> Vec<i16> {
    let bytes = std::fs::read(path).unwrap_or_else(|error| panic!("reading {path:?}: {error}"));
    let mut words = Vec::with_capacity(bytes.len() / 2);
    let mut at = 0;
    while at + 1 < bytes.len() {
        words.push(i16::from_le_bytes([bytes[at], bytes[at + 1]]));
        at += 2;
    }
    words
}

#[test]
fn decodes_every_itu_test_sequence_bit_exactly() {
    let Some(dir) = vectors_dir() else {
        eprintln!("skipping: reference/g729/testv/base absent (see reference/g729/README.md)");
        return;
    };

    for (name, exercises) in SEQUENCES {
        let bitstream = read_words(&dir.join(format!("{name}.bit")));
        let expected = read_words(&dir.join(format!("{name}.pst")));

        let mut decoder = G729Decoder::new();
        let mut produced = Vec::with_capacity(expected.len());

        let mut start = 0;
        while start + SERIAL_WORDS <= bitstream.len() {
            let bits = &bitstream[start + 2..start + SERIAL_WORDS];
            start += SERIAL_WORDS;
            // The serial format signals a lost frame by zeroing its bit words; on the wire that
            // information comes from the jitter buffer instead, which is why the decoder takes it as
            // an argument rather than inferring it from the payload.
            if bits.contains(&0) {
                produced.extend_from_slice(&decoder.conceal());
                continue;
            }
            let mut packed = [0_u8; 10];
            for (index, &word) in bits.iter().enumerate() {
                if word == BIT_SET {
                    packed[index / 8] |= 1 << (7 - index % 8);
                }
            }
            let samples = decoder
                .decode(&packed)
                .unwrap_or_else(|error| panic!("{name}: decoding a 10-octet frame: {error}"));
            produced.extend_from_slice(&samples);
        }

        assert_eq!(
            produced.len(),
            expected.len(),
            "{name} ({exercises}): decoded {} samples, reference has {}",
            produced.len(),
            expected.len()
        );
        if let Some((index, (&got, &want))) = produced
            .iter()
            .zip(expected.iter())
            .enumerate()
            .find(|(_, (got, want))| got != want)
        {
            panic!(
                "{name} ({exercises}) diverges at sample {index} (frame {}, offset {}): \
                 got {got}, reference has {want}",
                index / 80,
                index % 80
            );
        }
    }
}

#[test]
fn a_frame_that_is_not_ten_octets_is_refused() {
    // The conformance sequences only ever present well-formed frames. On the wire a payload can be
    // any length at all, and the decoder has to say no rather than read past its end.
    let mut decoder = G729Decoder::new();
    assert!(decoder.decode(&[]).is_err());
    assert!(decoder.decode(&[0; 9]).is_err());
    assert!(decoder.decode(&[0; 11]).is_err());
    assert!(
        decoder.decode(&[0; 10]).is_ok(),
        "any 80-bit pattern decodes"
    );
}

#[test]
fn concealment_runs_without_a_single_good_frame() {
    // A stream that opens with loss has no state to conceal from. It must still produce audio of
    // the right length rather than panicking on its own initial state.
    let mut decoder = G729Decoder::new();
    for _ in 0..50 {
        assert_eq!(decoder.conceal().len(), 80);
    }
}
