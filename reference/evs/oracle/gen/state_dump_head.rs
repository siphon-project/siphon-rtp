//! A walk over every field of the decoder state, for oracles that compare the whole state.
//!
//! The `visit_*` functions below are generated, together with the `rd_dump_*` / `rd_fill_*`
//! functions of `reference/evs/oracle/fn/init_dec.c`, by one gdb walk over the reference's debug
//! info for `Decoder_State_fx` (field names by the rules of `oracle/state_export.py`), so both
//! sides list the same fields in the same order under the same keys (the C field paths).
//! Regenerate both together whenever `gen_state.sh` changes the state.
//! A [`StateVisitor`] either dumps the state as the oracle prints it, fills every integer field
//! with the oracle's deterministic pattern, or loads a state the oracle printed.
//!
//! Pointers: a ROM table is compared on its first entries (it is not loaded: init sets it, and the
//! init oracle proves that); a pointer into the state's own arrays is an offset (or a row index),
//! -1 for NULL; an owned buffer (`Vec`) is compared and loaded in full.

#![allow(clippy::too_many_lines, dead_code)]

use std::collections::BTreeMap;

use siphon_rtp_codec::evs::dec::state::*;
use siphon_rtp_codec::evs::rom::types::{PWord16, TnsParameters};

use crate::tns_base::{table_from_id, table_id};

/// The oracle's `rd_pattern_next`: an LCG in [-16384, 16383].
#[derive(Debug, Clone, Copy)]
pub struct Pattern(pub u32);

impl Pattern {
    fn next(&mut self) -> i32 {
        self.0 = self.0.wrapping_mul(1_103_515_245).wrapping_add(12345);
        ((self.0 >> 16) & 0x7fff) as i32 - 16384
    }
}

/// An integer field (or nested array of them) as the oracle prints it.
pub trait Leaf {
    fn put(&self, out: &mut Vec<i64>);
    fn take(&mut self, values: &mut std::slice::Iter<'_, i64>);
    fn fill(&mut self, pattern: &mut Pattern);
}

macro_rules! leaf {
    ($($t:ty => $fill:expr),*) => {$(
        impl Leaf for $t {
            fn put(&self, out: &mut Vec<i64>) {
                out.push(i64::from(*self));
            }
            fn take(&mut self, values: &mut std::slice::Iter<'_, i64>) {
                *self = *values.next().expect("enough values") as $t;
            }
            #[allow(clippy::redundant_closure_call)]
            fn fill(&mut self, pattern: &mut Pattern) {
                *self = ($fill)(pattern.next());
            }
        }
    )*};
}
leaf!(
    i8 => |v: i32| v as i8,
    u8 => |v: i32| v as u8,
    i16 => |v: i32| v as i16,
    u16 => |v: i32| v as u16,
    i32 => |v: i32| v.wrapping_mul(65537),
    u32 => |v: i32| v.wrapping_mul(65537) as u32
);

impl<T: Leaf, const N: usize> Leaf for [T; N] {
    fn put(&self, out: &mut Vec<i64>) {
        for x in self {
            x.put(out);
        }
    }
    fn take(&mut self, values: &mut std::slice::Iter<'_, i64>) {
        for x in self {
            x.take(values);
        }
    }
    fn fill(&mut self, pattern: &mut Pattern) {
        for x in self {
            x.fill(pattern);
        }
    }
}

impl Leaf for PWord16 {
    fn put(&self, out: &mut Vec<i64>) {
        self.v.re.put(out);
        self.v.im.put(out);
    }
    fn take(&mut self, values: &mut std::slice::Iter<'_, i64>) {
        self.v.re.take(values);
        self.v.im.take(values);
    }
    fn fill(&mut self, pattern: &mut Pattern) {
        self.v.re.fill(pattern);
        self.v.im.fill(pattern);
    }
}

/// What a walk does at each field.
pub enum Mode<'a> {
    /// Collect `(key, values)` in walk order.
    Dump(Vec<(String, Vec<i64>)>),
    /// Fill every integer field from the pattern.
    Fill(Pattern),
    /// Load every field from an oracle dump.
    Load(&'a BTreeMap<String, Vec<i64>>),
}

pub struct StateVisitor<'a> {
    pub mode: Mode<'a>,
    /// Keys of ROM pointers: the oracle prints a fixed number of entries, reading past the end of
    /// a short table, so these compare as a prefix (empty only against NULL).
    pub rom_keys: std::collections::BTreeSet<String>,
}

impl StateVisitor<'_> {
    fn loaded(&self, key: &str) -> Option<&[i64]> {
        match &self.mode {
            Mode::Load(map) => Some(
                map.get(key)
                    .unwrap_or_else(|| panic!("no {key} in the oracle dump")),
            ),
            _ => None,
        }
    }

    fn push(&mut self, key: String, values: Vec<i64>) {
        if let Mode::Dump(out) = &mut self.mode {
            out.push((key, values));
        }
    }

    fn leaf_inner<T: Leaf>(&mut self, pre: &str, name: &str, x: &mut T, fill: bool) {
        let key = format!("{pre}{name}");
        match &mut self.mode {
            Mode::Dump(out) => {
                let mut values = Vec::new();
                x.put(&mut values);
                out.push((key, values));
            }
            Mode::Fill(pattern) => {
                if fill {
                    x.fill(pattern);
                }
            }
            Mode::Load(map) => {
                let values = map
                    .get(&key)
                    .unwrap_or_else(|| panic!("no {key} in the oracle dump"));
                let mut it = values.iter();
                x.take(&mut it);
                assert!(it.next().is_none(), "{key}: too many values");
            }
        }
    }

    pub fn leaf<T: Leaf>(&mut self, pre: &str, name: &str, x: &mut T) {
        self.leaf_inner(pre, name, x, true);
    }

    /// A field the pattern fill leaves alone (an input set before the call).
    pub fn leaf_no_fill<T: Leaf>(&mut self, pre: &str, name: &str, x: &mut T) {
        self.leaf_inner(pre, name, x, false);
    }

    pub fn rom16(&mut self, pre: &str, name: &str, table: &'static [i16]) {
        let values = table.iter().take(8).map(|&v| i64::from(v)).collect();
        self.rom_keys.insert(format!("{pre}{name}"));
        self.push(format!("{pre}{name}"), values);
    }

    pub fn romp16(&mut self, pre: &str, name: &str, table: &'static [PWord16]) {
        let mut values = Vec::new();
        for x in table.iter().take(8) {
            x.put(&mut values);
        }
        self.rom_keys.insert(format!("{pre}{name}"));
        self.push(format!("{pre}{name}"), values);
    }

    pub fn tns(&mut self, pre: &str, name: &str, table: &mut &'static [TnsParameters]) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            *table = table_from_id(values[0] as i16);
        } else {
            self.push(key, vec![i64::from(table_id(table))]);
        }
    }

    pub fn tns_pointer(&mut self, pre: &str, name: &str, pointer: &mut Option<(usize, usize)>) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            *pointer = usize::try_from(values[0]).ok().map(|i| (i / 2, i % 2));
        } else {
            let value = pointer.map_or(-1, |(i, j)| (i * 2 + j) as i64);
            self.push(key, vec![value]);
        }
    }

    pub fn offset(&mut self, pre: &str, name: &str, offset: &mut usize) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            *offset = usize::try_from(values[0]).expect("an offset");
        } else {
            self.push(key, vec![*offset as i64]);
        }
    }

    pub fn offset_opt(&mut self, pre: &str, name: &str, offset: &mut Option<usize>) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            *offset = usize::try_from(values[0]).ok();
        } else {
            self.push(key, vec![offset.map_or(-1, |o| o as i64)]);
        }
    }

    pub fn vec16(&mut self, pre: &str, name: &str, buffer: &mut Vec<i16>) {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            buffer.clear();
            buffer.extend(values.iter().map(|&v| v as i16));
        } else {
            let values = buffer.iter().map(|&v| i64::from(v)).collect();
            self.push(key, values);
        }
    }

    pub fn handle<'h, T>(
        &mut self,
        pre: &str,
        name: &str,
        handle: &'h mut Option<Box<T>>,
    ) -> Option<&'h mut T> {
        let key = format!("{pre}{name}");
        if let Some(values) = self.loaded(&key) {
            assert_eq!(
                values[0] != 0,
                handle.is_some(),
                "{key}: handle presence differs from the dump"
            );
        } else {
            self.push(key, vec![i64::from(handle.is_some())]);
        }
        handle.as_deref_mut()
    }
}

/// The whole state as the oracle prints it, keyed `st.<C path>`.
pub fn dump(st: &mut DecoderState) -> Vec<(String, Vec<i64>)> {
    let mut v = StateVisitor {
        mode: Mode::Dump(Vec::new()),
        rom_keys: std::collections::BTreeSet::new(),
    };
    visit_decoder_state(&mut v, "st.", st);
    match v.mode {
        Mode::Dump(out) => out,
        _ => unreachable!(),
    }
}

/// Fill every integer field with the oracle's pattern from `seed`, as `rd_fill_DecoderState`.
pub fn fill(st: &mut DecoderState, seed: u32) {
    let mut v = StateVisitor {
        mode: Mode::Fill(Pattern(seed)),
        rom_keys: std::collections::BTreeSet::new(),
    };
    visit_decoder_state(&mut v, "st.", st);
}

/// Load a state the oracle printed with prefix `pre` (handles must already exist).
pub fn load(st: &mut DecoderState, side: &BTreeMap<String, Vec<i64>>, pre: &str) {
    let mut v = StateVisitor {
        mode: Mode::Load(side),
        rom_keys: std::collections::BTreeSet::new(),
    };
    visit_decoder_state(&mut v, pre, st);
}

/// Compare the whole state with an oracle dump printed with prefix `pre`; panics listing the
/// first differing fields (and any field one side has and the other lacks).
pub fn check(st: &mut DecoderState, side: &BTreeMap<String, Vec<i64>>, pre: &str, context: &str) {
    let mut v = StateVisitor {
        mode: Mode::Dump(Vec::new()),
        rom_keys: std::collections::BTreeSet::new(),
    };
    visit_decoder_state(&mut v, pre, st);
    let rom_keys = v.rom_keys;
    let Mode::Dump(rust) = v.mode else {
        unreachable!()
    };
    let mut differences = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (key, values) in &rust {
        seen.insert(key.as_str());
        match side.get(key) {
            None => differences.push(format!("{key}: missing from the oracle dump")),
            Some(reference)
                if rom_keys.contains(key)
                    && reference.starts_with(values)
                    && values.is_empty() == reference.is_empty() => {}
            Some(reference) if reference != values => {
                let first = values
                    .iter()
                    .zip(reference)
                    .position(|(a, b)| a != b)
                    .unwrap_or(values.len().min(reference.len()));
                differences.push(format!(
                    "{key}: first difference at [{first}] (len rust {} ref {}): rust {:?} ref {:?}",
                    values.len(),
                    reference.len(),
                    values.get(first..(first + 8).min(values.len())),
                    reference.get(first..(first + 8).min(reference.len())),
                ));
            }
            Some(_) => {}
        }
    }
    for key in side.keys() {
        if key.starts_with(pre) && !seen.contains(key.as_str()) {
            differences.push(format!("{key}: in the oracle dump, not in the Rust walk"));
        }
    }
    assert!(
        differences.is_empty(),
        "{context}: {} fields differ:\n  {}",
        differences.len(),
        differences
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

// ---------------- generated ----------------

